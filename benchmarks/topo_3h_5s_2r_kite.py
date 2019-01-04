from time import sleep

from mininet.cli import CLI
from mininet.node import Node, OVSBridge
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

from mininet.clean import cleanup as net_cleanup


#mininet patch
from mininet.log import error
from mininet.link import TCIntf
@staticmethod
def delayCmds(parent, delay=None, jitter=None,
              loss=None, max_queue_size=None ):
    "Internal method: return tc commands for delay and loss"
    cmds = []
    if delay and delay < 0:
        error( 'Negative delay', delay, '\n' )
    elif jitter and jitter < 0:
        error( 'Negative jitter', jitter, '\n' )
    elif loss and ( loss < 0 or loss > 100 ):
        error( 'Bad loss percentage', loss, '%%\n' )
    else:
        # Delay/jitter/loss/max queue size
        netemargs = '%s%s%s%s' % (
            'delay %s ' % delay if delay is not None else '',
            '%s ' % jitter if jitter is not None else '',
            'loss %0.4f ' % loss if loss is not None and loss > 0 else '',  # The fix
            'limit %d' % max_queue_size if max_queue_size is not None
            else '' )
        if netemargs:
            cmds = [ '%s qdisc add dev %s ' + parent +
                     ' handle 10: netem ' +
                     netemargs ]
            parent = ' parent 10:1 '
    return cmds, parent
TCIntf.delayCmds = delayCmds
# end mininet patch


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
        generic_opts = {'delay': '5ms', 'max_queue_size': 3 * 174}
        self.r1 = self.addNode('r1', cls=LinuxRouter)
        self.r2 = self.addNode('r2', cls=LinuxRouter)
        self.r3 = self.addNode('r3', cls=LinuxRouter)

        for s in ('s1', 's2', 's3', 's4'):
            setattr(self, s, self.addSwitch(s))

        if 'bw_b' in opts and 'delay_ms_b' in opts:
            mqs = int(1.5 * (((opts['bw_b'] * 1000000) / 8) / 1500) * (2 * 70 / 1000.0))  # 1.5 * BDP, TODO: This assumes that packet size is 1500 bytes
            self.addLink(self.s1, self.r1, bw=opts['bw_b'], delay='%dms' % opts['delay_ms_b'], loss=opts.get('loss_b', 0), max_queue_size=mqs, intfName2='r1-eth0')
        else:
            self.addLink(self.s1, self.r1, intfName2='r1-eth0')
        self.addLink(self.s3, self.r1, intfName2='r1-eth2', **generic_opts)
        if 'bw_a' in opts and 'delay_ms_a' in opts:
            mqs = int(1.5 * (((opts['bw_a'] * 1000000) / 8) / 1500) * (2 * 70 / 1000.0))  # 1.5 * BDP, TODO: This assumes that packet size is 1500 bytes
            self.addLink(self.s2, self.r2, bw=opts['bw_a'], delay='%dms' % opts['delay_ms_a'], loss=opts.get('loss_a', 0), max_queue_size=mqs, intfName2='r2-eth0')
        else:
            self.addLink(self.s2, self.r2, intfName2='r1-eth0')
        self.addLink(self.s4, self.r3, intfName2='r3-eth0', **generic_opts)

        self.cl = self.addHost('cl')
        self.vpn = self.addHost('vpn')
        self.web = self.addHost('web')

        self.addLink(self.cl, self.s1, intfName1='cl-eth0')
        self.addLink(self.cl, self.s2, intfName1='cl-eth1')
        self.addLink(self.r1, self.r3, intfName1='r1-eth1', intfName2='r3-eth1', **generic_opts)
        self.addLink(self.r2, self.r3, intfName1='r2-eth1', intfName2='r3-eth2', **generic_opts)
        self.addLink(self.vpn, self.s4, intfName1='vpn-eth0')
        self.addLink(self.web, self.s3, intfName1='web-eth0')


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
        'r3': {
            'r3-eth0': '10.2.2.1/24',
            'r3-eth1': '10.2.0.2/24',
            'r3-eth2': '10.2.1.2/24',
        },
        'cl': {
            'cl-eth0': '10.1.0.2/24',
            'cl-eth1': '10.1.1.2/24',
            'default': 'via 10.1.0.1 dev cl-eth0'
        },
        'vpn': {
            'vpn-eth0': '10.2.2.2/24',
            'default': 'via 10.2.2.1 dev vpn-eth0'
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


def setup_routes(net):
    vpn_addr = '10.2.2.2'
    web_addr = '10.3.0.2'
    cl_addr1 = '10.1.0.2'
    cl_addr2 = '10.1.1.2'

    print net['r1'].cmd('ip route add {} via 10.2.0.2 dev r1-eth1'.format(vpn_addr))

    print net['r2'].cmd('ip route add {} via 10.2.1.2 dev r2-eth1'.format(web_addr))
    print net['r2'].cmd('ip route add {} via 10.2.1.2 dev r2-eth1'.format(vpn_addr))

    print net['r3'].cmd('ip route add {} via 10.2.0.1 dev r3-eth1'.format(cl_addr1))
    print net['r3'].cmd('ip route add {} via 10.2.1.1 dev r3-eth2'.format(cl_addr2))
    print net['r3'].cmd('ip route add {} via 10.2.0.1 dev r3-eth1'.format(web_addr))


def setup_client_tun(nodes, id):
    tun_addr = '10.4.0.2/24'
    web_addr = '10.3.0.2'
    node = nodes[id]

    print node.cmd('modprobe tun')
    print node.cmd('ip tuntap add mode tun dev tun0')
    print node.cmd('ip addr add {} dev tun0'.format(tun_addr))
    print node.cmd('ip link set dev tun0 mtu 1400')
    print node.cmd('ip link set dev tun0 up')

    print node.cmd('ip route add {} via {} dev tun0'.format(web_addr, tun_addr[:-3]))

    print node.cmd('ip rule add from 10.1.0.2 table 1')
    print node.cmd('ip route add 10.1.0.0/24 dev cl-eth0 scope link table 1')
    print node.cmd('ip route add default via 10.1.0.1 dev cl-eth0 table 1')
    print node.cmd('ip rule add from 10.1.1.2 table 2')
    print node.cmd('ip route add 10.1.1.0/24 dev cl-eth1 scope link table 2')
    print node.cmd('ip route add default via 10.1.1.1 dev cl-eth1 table 2')

    # The two following lines are very important!
    print node.cmd('ip route add default via 10.1.0.1 dev cl-eth0 metric 100')
    print node.cmd('ip route add default via 10.1.1.1 dev cl-eth1 metric 101')


def setup_server_tun(nodes, id, server_addr):
    tun_addr = '10.4.0.1/24'
    node = nodes[id]

    print node.cmd('modprobe tun')
    print node.cmd('ip tuntap add mode tun dev tun1')
    print node.cmd('ip addr add {} dev tun1'.format(tun_addr))
    print node.cmd('ip link set dev tun1 mtu 1400')
    print node.cmd('ip link set dev tun1 up')

    print node.cmd('sysctl net.ipv4.ip_forward=1')
    print node.cmd('iptables -t nat -A POSTROUTING -o {}-eth0 -j SNAT --to {}'.format(id, server_addr))


def ping_matrix(net):
    def ping_cmd(node, ip):
        return net[node].cmd('ping -i 0.25 -c 4 -w 2 -s 1472 {}'.format(ip))

    nodes = ('cl', 'web', 'vpn', 'r1', 'r2', 'r3')
    for n1 in nodes:
        for n2 in nodes:
            if n1 is n2:
                continue
            for ip in net[n2].cmd('ip addr | grep -o -P "10.\d+.\d+.\d+"').splitlines():
                print "%s -> %s @ %s" % (n1, n2, ip)
                print ping_cmd(n1, ip)


def setup_net(net, ip_tun=True, quic_tun=True, gdb=False, tcpdump=False, multipath=False):
    setup_ips(net)
    setup_routes(net)

    vpn_addr = '10.2.2.2'

    if ip_tun:
        setup_client_tun(net, 'cl')
        setup_server_tun(net, 'vpn', vpn_addr)

    #ping_matrix(net)

    net['cl'].cmd('ping -i 0.25 -I cl-eth0 -c 4 {}'.format(vpn_addr))
    net['cl'].cmd('ping -i 0.25 -I cl-eth1 -c 4 {}'.format(vpn_addr))
    net['vpn'].cmd('ping -i 0.25 -c 4 {}'.format('10.1.1.2'))
    net['vpn'].cmd('ping -i 0.25 -c 4 {}'.format('10.1.0.2'))

    if quic_tun and tcpdump:
        net['cl'].cmd('tcpdump -i cl-eth0 -w cl1.pcap &')
        net['cl'].cmd('tcpdump -i cl-eth1 -w cl2.pcap &')
        net['vpn'].cmd('tcpdump -i tun1 -w tun1.pcap &')
        net['r1'].cmd('tcpdump -i r1-eth0 -w r10.pcap &')
        net['r1'].cmd('tcpdump -i r1-eth1 -w r11.pcap &')
        net['r1'].cmd('tcpdump -i r1-eth2 -w r12.pcap &')
        net['r2'].cmd('tcpdump -i r2-eth0 -w r20.pcap &')
        net['r2'].cmd('tcpdump -i r2-eth1 -w r21.pcap &')
        net['r3'].cmd('tcpdump -i r3-eth0 -w r30.pcap &')
        net['r3'].cmd('tcpdump -i r3-eth1 -w r31.pcap &')
        net['r3'].cmd('tcpdump -i r3-eth2 -w r32.pcap &')
        net['vpn'].cmd('tcpdump -i vpn-eth0 -w vpn.pcap &')
        sleep(1)

    plugins = "-P plugins/datagram/datagram.plugin"
    if multipath:
        plugins += " -P plugins/multipath/multipath.plugin"

    if quic_tun:
        if gdb:
            net['vpn'].cmd('gdb -batch -ex run -ex bt --args picoquicvpn {} -p 4443 2>&1 > log_server.log &'.format(plugins))
        else:
            net['vpn'].cmd('./picoquicvpn {} -p 4443 2>&1 > log_server.log &'.format(plugins))
        sleep(1)

    if tcpdump:
        if quic_tun:
            net['cl'].cmd('tcpdump -i tun0 -w tun0.pcap &')
        net['web'].cmd('tcpdump -i web-eth0 -w web.pcap &')
        sleep(1)

    if quic_tun:
        if gdb:
            net['cl'].cmd('gdb -batch -ex run -ex bt --args picoquicvpn {} 10.2.2.2 4443 2>&1 > log_client.log &'.format(plugins))
        else:
            net['cl'].cmd('./picoquicvpn {} 10.2.2.2 4443 2>&1 > log_client.log &'.format(plugins))

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
    net = Mininet(KiteTopo(bw_a=10, bw_b=10, delay_ms_a=10, delay_ms_b=10, loss_a=0, loss_b=0), link=TCLink, autoStaticArp=True, switch=OVSBridge, controller=None)
    net.start()
    setup_net(net, ip_tun=True, quic_tun=True, gdb=False, tcpdump=True, multipath=True)

    CLI(net)
    teardown_net(net)
    net.stop()
    net_cleanup()


if __name__ == '__main__':
    setLogLevel('info')
    run()
