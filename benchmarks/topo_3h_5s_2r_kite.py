from time import sleep

from mininet.cli import CLI
from mininet.node import Node, CPULimitedHost
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

from mininet.clean import cleanup as net_cleanup

class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class KiteTopo(Topo):
    def build(self, **opts):
        self.r1 = self.addNode('r1', cls=LinuxRouter)
        self.r2 = self.addNode('r2', cls=LinuxRouter)

        for s in ('s1', 's2', 's3', 's4', 's5'):
            setattr(self, s, self.addSwitch(s))

        if 'bw_b' in opts and 'loss_b' in opts and 'delay_ms_b' in opts:
            mqs = int(1.5 * (((opts['bw_b'] * 1000000) / 8) / 1200) * (2 * opts['delay_ms_b'] / 1000.0))  # 1.5 * BDP, TODO: This assumes that packet size is 1200 bytes
            self.addLink(self.s1, self.r1, bw=opts['bw_b'], delay='%dms' % opts['delay_ms_b'], loss=opts['loss_b'], max_queue_size=mqs)
        else:
            self.addLink(self.s1, self.r1)
        self.addLink(self.s2, self.r1)
        self.addLink(self.s3, self.r1)
        if 'bw_a' in opts and 'loss_a' in opts and 'delay_ms_a' in opts:
            mqs = int(1.5 * (((opts['bw_a'] * 1000000) / 8) / 1200) * (2 * opts['delay_ms_a'] / 1000.0))  # 1.5 * BDP, TODO: This assumes that packet size is 1200 bytes
            self.addLink(self.s4, self.r2, bw=opts['bw_a'], delay='%dms' % opts['delay_ms_a'], loss=opts['loss_a'], max_queue_size=mqs)
        else:
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


def setup_net(net, ip_tun=True, quic_tun=True, gdb=False, tcpdump=False):
    setup_ips(net)

    if not ip_tun:
        return

    setup_client_tun(net, 'cl', ('10.2.0.2', '10.1.0.1', 'cl-eth0'), ('10.2.1.2', '10.1.1.1', 'cl-eth1'))
    setup_server_tun(net, 'vpn', '10.2.0.2', ('10.1.1.2', '10.2.1.1', 'vpn-eth1'))

    if not quic_tun:
        return

    if tcpdump:
        net['vpn'].cmd('tcpdump -i tun1 -w tun1.pcap &')
        net['vpn'].cmd('tcpdump -i vpn-eth0 -w vpn.pcap &')
        sleep(1)

    if gdb:
        net['vpn'].cmd('gdb -batch -ex run -ex bt --args picoquicvpn -P plugins/datagram/datagram.plugin -p 4443 2>&1 > log_server.log &')
    else:
        net['vpn'].cmd('xterm -e "./picoquicvpn -P plugins/datagram/datagram.plugin -p 4443 2>&1 > log_server.log" &')
    sleep(1)

    if tcpdump:
        net['cl'].cmd('tcpdump -i tun0 -w tun0.pcap &')
        net['web'].cmd('tcpdump -i web-eth0 -w web.pcap &')
        sleep(1)

    if gdb:
        net['cl'].cmd('gdb -batch -ex run -ex bt --args picoquicvpn -P plugins/datagram/datagram.plugin 10.2.0.2 4443 2>&1 > log_client.log &')
    else:
        net['cl'].cmd('xterm -e "./picoquicvpn -P plugins/datagram/datagram.plugin 10.2.0.2 4443 2>&1 > log_client.log" &')

    net['web'].cmd('python3 -m http.server 80 &')
    sleep(1)


def teardown_net(net):
    net['vpn'].cmd('pkill tcpdump')
    net['vpn'].cmd('pkill picoquicpvn')
    net['vpn'].cmd('pkill gdb')
    net['vpn'].cmd('pkill xterm')

    net['cl'].cmd('pkill tcpdump')
    net['cl'].cmd('pkill picoquicpvn')
    net['cl'].cmd('pkill gdb')
    net['cl'].cmd('pkill xterm')

    net['web'].cmd('pkill python3')


def run():
    net_cleanup()
    net = Mininet(KiteTopo(bw_a=10, bw_b=10, delay_ms_a=5, delay_ms_b=5, loss_a=0.1, loss_b=0.1), link=TCLink, host=CPULimitedHost)
    net.start()
    setup_net(net, ip_tun=True, quic_tun=True, gdb=False, tcpdump=True)

    CLI(net)
    teardown_net(net)
    net.stop()
    net_cleanup()


if __name__ == '__main__':
    setLogLevel('info')
    run()
