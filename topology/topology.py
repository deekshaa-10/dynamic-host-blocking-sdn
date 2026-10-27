#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class BlockingTopology(Topo):
    """One switch, three clients and one TCP server."""

    def build(self):
        s1 = self.addSwitch(
            "s1",
            protocols="OpenFlow13"
        )

        n1 = self.addHost("n1", ip="10.0.0.1/24")
        n2 = self.addHost("n2", ip="10.0.0.2/24")
        atk = self.addHost("atk", ip="10.0.0.3/24")
        srv = self.addHost("srv", ip="10.0.0.4/24")

        self.addLink(n1, s1)
        self.addLink(n2, s1)
        self.addLink(atk, s1)
        self.addLink(srv, s1)

def run():
    topo = BlockingTopology()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True
    )

    # Coordinate the port and OpenFlow version with Person 2.
    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653
    )

    try:
        info("*** Starting dynamic host blocking topology\n")
        net.start()

        info("*** Hosts and IP addresses:\n")
        for host in net.hosts:
            info(f"{host.name}: {host.IP()}\n")

        info("*** Entering Mininet CLI\n")
        CLI(net)

    finally:
        info("*** Stopping network\n")
        net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    run()
