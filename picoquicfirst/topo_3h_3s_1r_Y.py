from time import sleep

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node
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
        router = self.addNode('r0', cls=LinuxRouter, ip='10.1.0.1/24')

        s1, s2, s3 = [self.addSwitch(s) for s in ('s1', 's2', 's3')]

        self.addLink(s1, router, intfName2='r0-eth1', params2={'ip': '10.1.0.1/24'})
        self.addLink(s2, router, intfName2='r0-eth2', params2={'ip': '10.2.0.1/24'})
        self.addLink(s3, router, intfName2='r0-eth3', params2={'ip': '10.3.0.1/24'})

        cl = self.addHost('cl', ip='10.1.0.2/24', defaultRoute='via 10.1.0.1')
        vpn = self.addHost('vpn', ip='10.2.0.2/24', defaultRoute='via 10.2.0.1')
        web = self.addHost('web', ip='10.3.0.2/24', defaultRoute='via 10.3.0.1')

        self.addLink(cl, s1)
        self.addLink(vpn, s2)
        self.addLink(web, s3)


def setup_client_tun(nodes, id, gateway, vpn_addr):
    tun_addr = '10.4.0.2/24'
    node = nodes[id]

    node.cmd('modprobe tun')
    node.cmd('ip tuntap add mode tun dev tun0')
    node.cmd('ip addr add {} dev tun0'.format(tun_addr))
    node.cmd('ip link set dev tun0 up')

    node.cmd('ip route del default')
    node.cmd('ip route add default via {} dev tun0'.format(tun_addr[:-3]))
    node.cmd('ip route add {} via {} dev {}-eth0'.format(vpn_addr, gateway, id))


def setup_server_tun(nodes, id, server_addr):
    tun_addr = '10.4.0.1/24'
    node = nodes[id]

    node.cmd('modprobe tun')
    node.cmd('ip tuntap add mode tun dev tun1')
    node.cmd('ip addr add {} dev tun1'.format(tun_addr))
    node.cmd('ip link set dev tun1 up')

    node.cmd('sysctl net.ipv4.ip_forward=1')
    node.cmd('iptables -t nat -A POSTROUTING -o {}-eth0 -j SNAT --to {}'.format(id, server_addr))


def run():
    net = Mininet(topo=MyTopo())
    net.start()

    setup_client_tun(net, 'cl', '10.1.0.1', '10.2.0.2')
    setup_server_tun(net, 'vpn', '10.2.0.2')

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
