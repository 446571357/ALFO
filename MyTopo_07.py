#!/usr/bin/python
import os
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch,  Host, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from GetConfig import get_config

def myNetwork():
    args = get_config('/home/zeng/Desktop/attack/topo_config.yaml')
    S1 = args['core_switch_number']  # 核心交换机数
    switches_1 = []
    S2 = args['edge_switch_number']  # 边缘交换机数
    switches_2 = []
    H = args['host_number']  # 边缘交换机连接主机数

    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0 = net.addController(name='c0', controller=RemoteController, protocol='tcp', port=6633)

    info( '*** Add switches/APs\n')
    for i in range(S1):
        si = net.addSwitch('s{}'.format(i + 1), cls=OVSKernelSwitch, dpid='000000000000000{}'.format(i + 1))
        switches_1.append(si)
    for i in range(S2):
        si = net.addSwitch('s{}'.format(S1 + i + 1), cls=OVSKernelSwitch, dpid='000000000000000{}'.format(S1 + i + 1))
        switches_2.append(si)
        for sj in switches_1:
            net.addLink(si, sj)

    info( '*** Add hosts/stations\n')
    count = 0
    for sj in switches_2:
        for i in range(H):
            count += 1
            hi = net.addHost('h{}'.format(count), cls=Host, ip='10.0.0.{}'.format(count), mac='00:00:00:00:00:0{}'.format(count), defaultRoute=None)
            net.addLink(sj, hi)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches/APs\n')
    for i in range(S1 + S2):
        net.get('s{}'.format(i + 1)).start([c0])
        command = 'ovs-vsctl -- --id=@ft create Flow_Table flow_limit={0} overflow_policy=refuse -- set Bridge s{1} flow_tables=0=@ft'.format(args['flow_limit'][i], i + 1)
        os.system(command)

    for host in args['background_traffic_host']:
        if args['loop']:
            tcp = 'tcpreplay --loop=0 -i {0}-eth0 {1} -K Desktop/DataSet/{2}'.format(host, args['background_traffic_config'], args['background_traffic_file'])
        else:
            tcp = 'tcpreplay -i {0}-eth0 {1} -K Desktop/DataSet/{2}'.format(host, args['background_traffic_config'], args['background_traffic_file'])
        print(tcp, "\n")
        net.get(host).popen(tcp)

    return net

if __name__ == '__main__':
    print('---------Topo Start:', time.asctime(time.localtime()), time.time())
    setLogLevel( 'info' )
    net = myNetwork()
    CLI(net)
    net.stop()
    # print('---------Topo End:', time.asctime(time.localtime()), time.time())

