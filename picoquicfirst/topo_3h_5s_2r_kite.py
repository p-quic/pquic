from time import sleep

from mininet.cli import CLI
from mininet.node import Node, CPULimitedHost
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo


class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class MyTopo(Topo):
    def build(self, **_opts):
        self.r1 = self.addNode('r1', cls=LinuxRouter)
        self.r2 = self.addNode('r2', cls=LinuxRouter)

        for s in ('s1', 's2', 's3', 's4', 's5'):
            setattr(self, s, self.addSwitch(s))

        self.addLink(self.s1, self.r1)
        self.addLink(self.s2, self.r1)
        self.addLink(self.s3, self.r1)
        self.addLink(self.s4, self.r2)
        self.addLink(self.s5, self.r2)

        self.cl = self.addHost('cl')
        self.vpn = self.addHost('vpn')
        self.web = self.addHost('web')

        self.addLink(self.cl, self.s1)
        self.addLink(self.cl, self.s4)
        self.addLink(self.vpn, self.s2)
        self.addLink(self.vpn, self.s5)
        self.addLink(self.web, self.s3)


def setup_ips(net):
    config = {
        'r1': {
            'r1-eth0': '10.1.0.1/24',
            'r1-eth1': '10.2.0.1/24',
            'r1-eth2': '10.3.0.1/24'
        },
        'r2': {
            'r2-eth0': '10.1.1.1/24',
            'r2-eth1': '10.2.1.1/24'
        },
        'cl': {
            'cl-eth0': '10.1.0.2/24',
            'cl-eth1': '10.1.1.2/24',
            'default': 'via 10.1.0.1 dev cl-eth0'
        },
        'vpn': {
            'vpn-eth0': '10.2.0.2/24',
            'vpn-eth1': '10.2.1.2/24',
            'default': 'via 10.2.0.1 dev vpn-eth0'
        },
        'web': {
            'web-eth0': '10.3.0.2/24',
            'default': 'via 10.3.0.1 dev web-eth0'
        }
    }

    for h in config:
        for intf, ip in sorted(config[h].items(), key=lambda x: x[0] == 'default'):
            if intf != 'default':
                print net[h].cmd('ip addr flush dev {}'.format(intf))
                print net[h].cmd('ip addr add {} dev {}'.format(ip, intf))
            else:
                print net[h].cmd('ip route add default {}'.format(ip))


def setup_client_tun(nodes, id, *static_routes):
    tun_addr = '10.4.0.2/24'
    node = nodes[id]

    node.cmd('modprobe tun')
    node.cmd('ip tuntap add mode tun dev tun0')
    node.cmd('ip addr add {} dev tun0'.format(tun_addr))
    node.cmd('ip link set dev tun0 up')

    node.cmd('ip route del default')
    node.cmd('ip route add default via {} dev tun0'.format(tun_addr[:-3]))
    for vpn_addr, gateway, oif in static_routes:
        print node.cmd('ip route add {} via {} dev {}'.format(vpn_addr, gateway, oif))


def setup_server_tun(nodes, id, server_addr, *static_routes):
    tun_addr = '10.4.0.1/24'
    node = nodes[id]

    node.cmd('modprobe tun')
    node.cmd('ip tuntap add mode tun dev tun1')
    node.cmd('ip addr add {} dev tun1'.format(tun_addr))
    node.cmd('ip link set dev tun1 up')

    node.cmd('sysctl net.ipv4.ip_forward=1')
    node.cmd('iptables -t nat -A POSTROUTING -o {}-eth0 -j SNAT --to {}'.format(id, server_addr))
    for vpn_addr, gateway, oif in static_routes:
        print node.cmd('ip route add {} via {} dev {}'.format(vpn_addr, gateway, oif))


def run():
    net = Mininet(MyTopo(), link=TCLink, host=CPULimitedHost)
    net.start()
    setup_ips(net)

    setup_client_tun(net, 'cl', ('10.2.0.2', '10.1.0.1', 'cl-eth0'), ('10.2.1.2', '10.1.1.1', 'cl-eth1'))
    setup_server_tun(net, 'vpn', '10.2.0.2', ('10.1.1.2', '10.2.1.1', 'vpn-eth1'))

    net['vpn'].cmd('sh -c "./picoquicvpn -P plugins/datagram/datagram.plugin -p 4443" > server.log &')
    net['vpn'].cmd('tcpdump -i tun1 -w tun1.pcap &')
    net['vpn'].cmd('tcpdump -i vpn-eth0 -w vpn.pcap &')
    sleep(0.25)
    net['cl'].cmd('sh -c "./picoquicvpn -P plugins/datagram/datagram.plugin 10.2.0.2 4443" > client.log &')
    net['cl'].cmd('tcpdump -i tun0 -w tun0.pcap &')

    net['web'].cmd('python3 -m http.server 80 &')
    net['web'].cmd('tcpdump -i web-eth0 -w web.pcap &')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
