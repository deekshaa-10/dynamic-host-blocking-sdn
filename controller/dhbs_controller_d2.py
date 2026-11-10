"""
Dynamic Host Blocking System - Ryu SDN controller v2 (OpenFlow 1.3), Deliverable 2

Built on the D1 controller (learning switch, per-connection flows, per-host
new-connection counting, drop rule on threshold). New in D2:

  1. Block -> unblock -> re-block cycle
     - A blocked host is unblocked automatically when its drop rule expires.
       The switch reports the expiry (OFPFlowRemoved), so UNBLOCK is logged
       immediately and not only when the host next sends traffic. A 1 s timer
       is a fallback if that message is ever lost.
     - If the host attacks again, it is blocked again (REBLOCK). Repeat
       offenders get a longer block each time (exponential backoff, capped).
       A host that behaves for DHBS_OFFENSE_RESET seconds starts from the base
       block time again.
  2. Multiple simultaneous attackers
     - All state is kept per source IP (own counter, own block, own timer),
       so any number of hosts are detected and blocked independently, and a
       slow or well-behaved host is never affected by the others.
  3. Machine-readable event log: logs/events.csv (BLOCK / REBLOCK / UNBLOCK)
     for the tests and the performance graphs, plus a periodic STATUS line.

Run:   ryu-manager controller/dhbs_controller.py
Tune with environment variables (all optional):
  DHBS_THRESHOLD          new connections allowed per window        (default 20)
  DHBS_WINDOW             sliding window, seconds                   (default 5)
  DHBS_BLOCK_SECONDS      first block duration, seconds (>= 1)      (default 60)
  DHBS_BACKOFF            block duration multiplier per repeat      (default 2)
  DHBS_MAX_BLOCK_SECONDS  cap on the block duration                 (default 480)
  DHBS_OFFENSE_RESET      good behaviour needed to reset offences   (default 300)
  DHBS_WHITELIST          comma-separated IPs never blocked         (default 10.0.0.4)
Example (fast demo):
  DHBS_BLOCK_SECONDS=15 DHBS_MAX_BLOCK_SECONDS=60 DHBS_WHITELIST=10.0.0.4 \
      ryu-manager controller/dhbs_controller.py
"""
import csv
import logging
import os
import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3


def _env_int(name, default):
    return int(os.environ.get(name, default))


# ----------------------------- tunables -----------------------------------
CONN_THRESHOLD = _env_int("DHBS_THRESHOLD", 20)
WINDOW_SECONDS = _env_int("DHBS_WINDOW", 5)
BLOCK_SECONDS = max(1, _env_int("DHBS_BLOCK_SECONDS", 60))
BACKOFF_FACTOR = max(1, _env_int("DHBS_BACKOFF", 2))
MAX_BLOCK_SECONDS = max(BLOCK_SECONDS, _env_int("DHBS_MAX_BLOCK_SECONDS", 480))
OFFENSE_RESET_SECONDS = _env_int("DHBS_OFFENSE_RESET", 300)
WHITELIST = {ip.strip() for ip in
             os.environ.get("DHBS_WHITELIST", "10.0.0.4").split(",") if ip.strip()}

FLOW_IDLE_TIMEOUT = 10      # per-connection flow idle timeout, seconds
FALLBACK_GRACE = 3          # timer fallback fires this long after expiry
STATUS_EVERY = 10           # STATUS log line period while hosts are blocked

PRIO_TABLE_MISS = 0
PRIO_FORWARD = 10
PRIO_BLOCK = 100


class DynamicHostBlocker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicHostBlocker, self).__init__(*args, **kwargs)
        self.mac_to_port = {}                  # dpid -> {mac: port}
        self.datapaths = {}                    # dpid -> datapath
        self.conn_times = defaultdict(deque)   # src ip -> timestamps of new connections
        self.blocked = {}                      # src ip -> block info (see _block_host)
        self.offenses = {}                     # src ip -> {"count", "last_unblock"}
        self._setup_logging()
        self.logger.info(
            "CONTROLLER_START threshold=%d window=%ds block=%ds backoff=x%d max_block=%ds "
            "offense_reset=%ds whitelist=%s",
            CONN_THRESHOLD, WINDOW_SECONDS, BLOCK_SECONDS, BACKOFF_FACTOR,
            MAX_BLOCK_SECONDS, OFFENSE_RESET_SECONDS, sorted(WHITELIST))
        self.monitor_thread = hub.spawn(self._monitor)

    # ------------------------------------------------------------------ logging
    def _setup_logging(self):
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
        os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(os.path.join(log_dir, "controller_events.log"))
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.csv_path = os.path.join(log_dir, "events.csv")
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["epoch", "time", "event", "host", "offense", "duration_s", "detail"])

    def _csv_event(self, event, host, offense="", duration="", detail=""):
        with open(self.csv_path, "a", newline="") as f:
            csv.writer(f).writerow([
                "%.3f" % time.time(), time.strftime("%H:%M:%S"),
                event, host, offense, duration, detail])

    # ------------------------------------------------------------- switch setup
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_TABLE_MISS, match, actions)
        self.logger.info("SWITCH_CONNECTED dpid=%s", dp.id)

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout))

    # ---------------------------------------------------------------- packet-in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # learning switch
        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None:
            if ip.src in self.blocked:
                return  # in-flight packet from a blocked host: drop

            tcp_h = pkt.get_protocol(tcp.tcp)
            udp_h = pkt.get_protocol(udp.udp)

            if self._is_new_connection(tcp_h, udp_h) and ip.src not in WHITELIST:
                count = self._record_connection(ip.src)
                self.logger.info(
                    "NEW_CONN src=%s dst=%s proto=%s count=%d/%d (window %ds)",
                    ip.src, ip.dst, "TCP" if tcp_h else "UDP", count,
                    CONN_THRESHOLD, WINDOW_SECONDS)
                if count > CONN_THRESHOLD:
                    self._block_host(ip.src, count)
                    return

            if out_port != ofp.OFPP_FLOOD:
                match = self._connection_match(parser, in_port, ip, tcp_h, udp_h)
                self._add_flow(dp, PRIO_FORWARD, match, actions,
                               idle_timeout=FLOW_IDLE_TIMEOUT)

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port,
            actions=actions, data=msg.data))

    # ------------------------------------------------- flow expiry -> unblock
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """The switch tells us a drop rule has expired: unblock the host now."""
        msg = ev.msg
        if msg.priority != PRIO_BLOCK:
            return
        try:
            src = msg.match["ipv4_src"]
        except KeyError:
            return
        info = self.blocked.get(src)
        if info is None:
            return
        info["dpids"].discard(msg.datapath.id)
        if not info["dpids"]:            # expired on every switch it was installed on
            self._unblock(src, "flow_expired")

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _is_new_connection(tcp_h, udp_h):
        if tcp_h is not None:
            return bool(tcp_h.bits & tcp.TCP_SYN) and not (tcp_h.bits & tcp.TCP_ACK)
        return udp_h is not None

    @staticmethod
    def _connection_match(parser, in_port, ip, tcp_h, udp_h):
        fields = dict(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                      ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
        if tcp_h is not None:
            fields.update(tcp_src=tcp_h.src_port, tcp_dst=tcp_h.dst_port)
        elif udp_h is not None:
            fields.update(udp_src=udp_h.src_port, udp_dst=udp_h.dst_port)
        return parser.OFPMatch(**fields)

    def _record_connection(self, src):
        now = time.time()
        q = self.conn_times[src]
        q.append(now)
        while q and now - q[0] > WINDOW_SECONDS:
            q.popleft()
        return len(q)

    def _block_host(self, src, count):
        if src in self.blocked:
            return
        now = time.time()

        # offence number: continues if the host re-offends soon after an unblock
        hist = self.offenses.get(src)
        if (hist is not None and hist.get("last_unblock") is not None
                and now - hist["last_unblock"] <= OFFENSE_RESET_SECONDS):
            offense = hist["count"] + 1
        else:
            offense = 1
        duration = int(min(BLOCK_SECONDS * (BACKOFF_FACTOR ** (offense - 1)),
                           MAX_BLOCK_SECONDS))
        self.offenses[src] = {"count": offense, "last_unblock": None}

        info = {"start": now, "until": now + duration, "offense": offense,
                "duration": duration, "dpids": set()}
        self.blocked[src] = info
        self.conn_times.pop(src, None)

        for dp in self.datapaths.values():
            ofp, parser = dp.ofproto, dp.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
            # empty instruction list == drop; SEND_FLOW_REM -> told when it expires
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=PRIO_BLOCK, match=match, instructions=[],
                hard_timeout=duration, flags=ofp.OFPFF_SEND_FLOW_REM))
            info["dpids"].add(dp.id)

        event = "BLOCK" if offense == 1 else "REBLOCK"
        self.logger.warning(
            "%s host=%s offense=%d duration=%ds reason=%d new connections in %ds (threshold %d)",
            event, src, offense, duration, count, WINDOW_SECONDS, CONN_THRESHOLD)
        self._csv_event(event, src, offense, duration, "count=%d" % count)

    def _unblock(self, src, reason):
        info = self.blocked.pop(src, None)
        if info is None:
            return
        now = time.time()
        self.offenses.setdefault(src, {"count": info["offense"]})["last_unblock"] = now
        self.conn_times.pop(src, None)          # start counting from zero
        held = int(now - info["start"])
        self.logger.info("UNBLOCK host=%s reason=%s offense=%d blocked_for=%ds",
                         src, reason, info["offense"], held)
        self._csv_event("UNBLOCK", src, info["offense"], held, reason)

    # ------------------------------------------------------- background timer
    def _monitor(self):
        last_status = 0.0
        while True:
            hub.sleep(1)
            now = time.time()
            self._expire_blocks(now)
            self._forget_idle_hosts(now)
            if self.blocked and now - last_status >= STATUS_EVERY:
                last_status = now
                parts = ["%s(offense %d, %ds left)" % (
                    ip, i["offense"], max(0, int(i["until"] - now)))
                    for ip, i in sorted(self.blocked.items())]
                self.logger.info("STATUS blocked=%d [%s]", len(parts), ", ".join(parts))

    def _expire_blocks(self, now):
        """Fallback: unblock if the flow-removed message never arrived."""
        for ip, info in list(self.blocked.items()):
            if now > info["until"] + FALLBACK_GRACE:
                self._unblock(ip, "timer_fallback")

    def _forget_idle_hosts(self, now):
        for ip in list(self.conn_times):
            q = self.conn_times[ip]
            while q and now - q[0] > WINDOW_SECONDS:
                q.popleft()
            if not q:
                del self.conn_times[ip]
