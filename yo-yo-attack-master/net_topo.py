from mininet.topo import Topo 
from mininet.net import Mininet 
from mininet.cli import CLI
from mininet.log import setLogLevel,info
from mininet.link import Link,Intf,TCLink
from mininet.util import dumpNodeConnections
from mininet.node import Node, RemoteController, Controller, OVSSwitch
import cmd
import os
import sys
import random
import time 


class Mytopo(Topo):
    """docstring for Mytopo"""
    def __init__(self):
        super(Mytopo, self).__init__()
        #Topo.__init__(self)
        info("-------add switch----------\n")
        s1 = self.addSwitch('s1')
        h = []
        info("-------add host------------\n")
        for i in range(1,21):
            h.append(self.addHost('h%d'%i))
        info("-------add link------------\n")
        for i in range(20):
            self.addLink(s1,h[i])
topos= {'mytopo':(lambda:Mytopo())}


def test():
    ip_list = []
    for i in range(1,21):
        ip_list.append('10.0.0.'+str(i))
    #print ip_list
    topo = Mytopo()
    c0 = RemoteController('c0',ip = '127.0.0.1',port = 6653)
    #c0 = Controller('c0')
    net  = Mininet(topo,controller = c0)
    net.start()
    #print net.switches
    '''
    for k in range(0,5):
        net.switches[k].cmd('ovs-vsctl set bridge s%d protocols=OpenFlow13'%(k))
    '''
    #net.switches[0].cmd('ovs-vsctl set bridge s1 protocols=OpenFlow13')
    #net.switch[0].cmd('ovs-vsctl set bridge s1 protocols=OpenFlow13')
    #net.pingAll()
    switch = net.switches[0]
    for y in range(1,20):
        switch.cmdPrint("ovs-ofctl add-flow s1 ip,nw_proto=1,priority=10,nw_dst=10.0.0."+str(y)+",actions=output:"+str(y))
    node_list = []
    for i in net.hosts:
        node_list.append(i)
    
    for i in range(0,20):
        if i<14:
            node_list[i].cmdPrint('python normal.py h%d&'%(i+1))
        #node_list[i].cmdPrint('python normalflow.py h%d&'%(i+1))
        #lse:
            #pass
            #node_list[i].cmdPrint('python hattac.py h%d %d &'%(i+1,5))
    
    '''
    for i in range(15,20):
        node_list[i].cmd('python attack7.py h%d %d'%(i+1,5))
        #node_list[i].cmdPrint('python attack7.py h%d %d'%(i+1,5))
    '''
    #info( "*** Stopping network\n" )
    CLI(net)
    #net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )  # for CLI output
    test()