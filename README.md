# Dynamic Host Blocking System (SDN + TCP Sockets)

Develop a system that identifies abnormal TCP traffic patterns and dynamically
blocks suspicious hosts using SDN flow rules. Built in Mininet with a Ryu
SDN controller and a custom multithreaded TCP socket application.

## Team Details

| Name | SRN | Contribution |
|------|-----|--------------|
| Abhinav Akinepalli | PES1UG25CS013 | Ryu SDN controller (`controller/`), integration testing, test cases |
| Deeksha A | PES1UG26CS813 | Socket application (`app/`), design document, README, architecture diagram |
| Adithyan | PES1UG25CS028 | Mininet topology (`topology/`) |

## What the system does

| Requirement | How it is met |
|-------------|---------------|
| Generate TCP traffic from multiple hosts | `app/client.py` (normal) and `app/attacker.py` (flood) run on separate Mininet hosts |
| Monitor connection rates | Controller counts new TCP connections (SYN without ACK) per source IP |
| Collect flow statistics | Per-connection flows installed on the switch; new connections reported to the controller |
| Define abnormal traffic thresholds | Configurable: >20 new connections in a 5 s sliding window |
| Detect suspicious hosts | A host crossing the threshold is flagged |
| Maintain a dynamic blocklist | Controller tracks blocked hosts with timed expiry |
| Install SDN drop rules | Priority-100 OpenFlow drop rule for the flagged host |
| Log detection and response events | `NEW_CONN`, `BLOCK`, `UNBLOCK` logged to `logs/controller_events.log` |

## Architecture

```
 n1 (normal, 10.0.0.1) ─┐
 n2 (normal, 10.0.0.2) ─┼── s1 (Open vSwitch, OpenFlow 1.3) ── srv (TCP server, 10.0.0.4)
 atk (attacker, 10.0.0.3)┘            │
                                      │ OpenFlow, 127.0.0.1:6653
                              Ryu controller (detect + block)
```

## Prerequisites

- Ubuntu 22.04 VM
- Mininet and Open vSwitch
- Ryu controller (needs Python 3.9 — it does not build on newer Python)

## Setup (once)

```bash
sudo apt update && sudo apt install -y mininet openvswitch-switch
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --seed --python 3.9 ~/ryu-env
source ~/ryu-env/bin/activate
pip install setuptools==67.6.1 wheel pbr eventlet==0.30.2
pip install --no-build-isolation ryu
```

## Run

```bash
git clone https://github.com/deekshaa-10/dynamic-host-blocking-sdn.git
cd dynamic-host-blocking-sdn
```

**Terminal 1 — controller**
```bash
source ~/ryu-env/bin/activate
ryu-manager controller/dhbs_controller.py
```

**Terminal 2 — topology**
```bash
sudo python3 topology/topology.py
```

Inside the Mininet CLI:
```bash
srv python3 app/server.py &
n1 python3 app/client.py --server 10.0.0.4
atk python3 app/attacker.py --server 10.0.0.4 --rate 50
```

## Verify

- **Detection/block log:** `cat logs/controller_events.log` (look for `BLOCK host=10.0.0.3`)
- **Drop rule on the switch:** in the Mininet CLI, `sh ovs-ofctl -O OpenFlow13 dump-flows s1`
- **Normal clients unaffected:** `n1`/`n2` still reach the server during the attack

## Cleanup

```bash
exit          # leave the Mininet CLI
sudo mn -c    # clear Mininet state
```

## Detection parameters (tunable)

| Parameter | Default | Env override |
|-----------|---------|--------------|
| Threshold | 20 new connections | `DHBS_THRESHOLD` |
| Window | 5 seconds | `DHBS_WINDOW` |
| Block duration | 60 seconds | `DHBS_BLOCK_SECONDS` |

The server (`10.0.0.4`) is whitelisted and never blocked.

## Repository layout

```
app/          TCP socket application (server, normal client, attacker)
controller/   Ryu SDN controller (dhbs_controller.py)
topology/     Mininet topology script
docs/         Architecture diagram and test screenshots
```
