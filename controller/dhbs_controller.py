"""
Dynamic Host Blocking System - Ryu SDN controller (OpenFlow 1.3)

What it does
  1. Learning switch: learns MAC -> port and forwards accordingly.
  2. Per-connection flow rules: every new TCP/UDP connection is sent to the
     controller once (packet-in); the controller installs an exact-match flow
     (src IP, dst IP, proto, src port, dst port) so the rest of that connection
     is forwarded by the switch without involving the controller.
  3. Detection: counts NEW connections per source host in a sliding time window.
     TCP: a SYN without ACK. UDP: first packet of a new 5-tuple.
  4. Mitigation: when a host exceeds the threshold, a high-priority DROP rule
     matching that source IP is installed on every switch.
  5. Logging: all events go to the console and to logs/controller_events.log.

Run:   ryu-manager controller/dhbs_controller.py
Tune:  edit the constants below, or override with environment variables, e.g.
       DHBS_THRESHOLD=10 DHBS_WINDOW=5 ryu-manager controller/dhbs_controller.py
"""
import logging
import os
import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

# ----------------------------- tunables -----------------------------------
CONN_THRESHOLD = int(os.environ.get("DHBS_THRESHOLD", 20))   # max new conns per window
WINDOW_SECONDS = int(os.environ.get("DHBS_WINDOW", 5))       # sliding window length
BLOCK_SECONDS = int(os.environ.get("DHBS_BLOCK_SECONDS", 60))  # 0 = block permanently
FLOW_IDLE_TIMEOUT = 10                                       # per-connection flow idle timeout
WHITELIST = {"10.0.0.4"}                                     # server IP - never blocked (confirm with Person 3)

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
        self.blocked = {}                      # src ip -> unblock time (None = permanent)
        self._setup_file_log()
        self.logger.info(
            "CONTROLLER_START threshold=%d window=%ds block=%ss whitelist=%s",
            CONN_THRESHOLD, WINDOW_SECONDS, BLOCK_SECONDS or "permanent", sorted(WHITELIST))

    # ------------------------------------------------------------------ logging
    def _setup_file_log(self):
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
        os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(os.path.join(log_dir, "controller_events.log"))
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------- switch setup
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        # table-miss: anything without a matching flow goes to the controller
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
            if self._is_blocked(ip.src):
                return  # drop silently (the DROP flow normally catches these first)

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

            # per-connection flow rule (only when destination port is known)
            if out_port != ofp.OFPP_FLOOD:
                match = self._connection_match(parser, in_port, ip, tcp_h, udp_h)
                self._add_flow(dp, PRIO_FORWARD, match, actions,
                               idle_timeout=FLOW_IDLE_TIMEOUT)

        # forward the packet that triggered the packet-in
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port,
            actions=actions, data=msg.data))

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _is_new_connection(tcp_h, udp_h):
        if tcp_h is not None:
            # SYN set, ACK not set -> first packet of a TCP handshake
            return bool(tcp_h.bits & tcp.TCP_SYN) and not (tcp_h.bits & tcp.TCP_ACK)
        return udp_h is not None  # first packet of a new UDP 5-tuple

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

    def _is_blocked(self, src):
        if src not in self.blocked:
            return False
        until = self.blocked[src]
        if until is not None and time.time() >= until:
            del self.blocked[src]
            self.logger.info("UNBLOCK host=%s (block expired)", src)
            return False
        return True

    def _block_host(self, src, count):
        self.blocked[src] = time.time() + BLOCK_SECONDS if BLOCK_SECONDS > 0 else None
        self.conn_times[src].clear()
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
            # empty instruction list == drop
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=PRIO_BLOCK, match=match, instructions=[],
                hard_timeout=BLOCK_SECONDS))
            self.logger.warning(
                "BLOCK host=%s dpid=%s reason=%d new connections in %ds (threshold %d) duration=%s",
                src, dp.id, count, WINDOW_SECONDS, CONN_THRESHOLD,
                "%ss" % BLOCK_SECONDS if BLOCK_SECONDS else "permanent")
