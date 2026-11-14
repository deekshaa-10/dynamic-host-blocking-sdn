```python
#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class BlockingTopology(Topo):
    """One switch, two normal clients, three attackers and one TCP server."""

    def build(self):

        # Create one OpenFlow 1.3 switch
        s1 = self.addSwitch("s1", protocols="OpenFlow13")

        # Create two legitimate client hosts
        n1 = self.addHost("n1", ip="10.0.0.1/24")
        n2 = self.addHost("n2", ip="10.0.0.2/24")

        # Create three attacker hosts
        atk = self.addHost("atk", ip="10.0.0.3/24")
        atk2 = self.addHost("atk2", ip="10.0.0.5/24")
        atk3 = self.addHost("atk3", ip="10.0.0.6/24")

        # Create the TCP server
        srv = self.addHost("srv", ip="10.0.0.4/24")

        # Connect all six hosts to the same switch
        self.addLink(n1, s1)
        self.addLink(n2, s1)
        self.addLink(atk, s1)
        self.addLink(atk2, s1)
        self.addLink(atk3, s1)
        self.addLink(srv, s1)


def run():

    topo = BlockingTopology()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True
    )

    # Connect to the existing Ryu controller
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
```
