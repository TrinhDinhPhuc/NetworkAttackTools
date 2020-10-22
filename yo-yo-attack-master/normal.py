from scapy.all import *
import random
import sys 
import fcntl
import time 

'''
def scale_flow(host_ip,rest_time,ip_mac):
def get_srcip(ifname):# get host ip
def get_dstip(host_ip):
def get_mac(src_ip,dst_ip):
'''

def scale_flow(host_ip,ip_mac):
    
    for i in range(0,5):
        src_ip = host_ip
        dst_ip = get_dstip(host_ip)
        src_mac = ip_mac.get(host_ip)
        dst_mac = ip_mac.get(dst_ip)
        pkt_len = random.randint(500,1200)
        ip_packet = Ether(src=src_mac,dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,600))/("i"*pkt_len)
        udp_packet = Ether(src=src_mac,dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,600))/("i"*pkt_len)
        sendp(ip_packet)
        sendp(udp_packet)

def get_srcip(ifname):# get host ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_dstip(host_ip):
    while 1:
        d = random.randint(1,20)#modify according to host num
        dst_ip = "10.0.0."+str(d) 
        if dst_ip != host_ip:
            return dst_ip

def get_mac(src_ip,dst_ip):
    arp_packet = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(psrc = src_ip,pdst = dst_ip)
    ant= srp1(arp_packet)
    return  ant.hwsrc

if __name__ == '__main__':
    ether_name = sys.argv[1]+"-eth0"
    host_ip = get_srcip(ether_name)
    ip_mac = {}
    ip_list = []

    for i in range(1,21):#get ip-mac dict
        dst_ip = "10.0.0."+str(i)
        if dst_ip !=  host_ip:
            ip_mac.setdefault(dst_ip,get_mac(host_ip,dst_ip))
    print ip_mac
    
    for i in range(1,21):#get ip_list
        ip_list.append("10.0.0."+str(i))
    #print ip_list
    tos_list = [15,25,63,79,30]#for random choose 
    src_ip = host_ip
    for i  in range(100):
    #while 1:
        tos = random.sample(tos_list,1)#choose a tos value
        #tos =25
        dst_ip = get_dstip(host_ip)
        
        print dst_ip
        #tos = 30
        if tos!=30:
            packet1 = Ether(src =ip_mac.get(src_ip) ,dst =ip_mac.get(dst_ip) )/IP(src = src_ip,dst = dst_ip,tos = tos)/UDP(sport = 1100,dport = (400,500))/('i'*20)
            sendp(packet1,inter=0.1)
            packet2 = Ether(src =ip_mac.get(src_ip) ,dst =ip_mac.get(dst_ip) )/IP(src = src_ip,dst = dst_ip,tos = tos)/UDP(sport = 1100,dport = (400,500))/('i'*20)
            sendp(packet2,inter=0.1)
            #time.sleep(0.5)
            '''
            packet1 = Ether(src =ip_mac.get(src_ip) ,dst =ip_mac.get(dst_ip) )/IP(src = src_ip,dst = dst_ip,tos = tos)/UDP(sport = random.randint(100,200),dport = (random.randint(100,200),random.randint(300,500)))/('i'*20)
            sendp(packet1)
            packet2 = Ether(src =ip_mac.get(src_ip) ,dst =ip_mac.get(dst_ip) )/IP(src = src_ip,dst = dst_ip,tos = tos)/TCP(sport = random.randint(100,200),dport = (random.randint(100,200),random.randint(300,500)))/('i'*20)
            sendp(packet2)
            '''

            #print "end-time: "+time.ctime()
        
        else:
            print "----------------------------------------"
            print "burst flow"
            print "----------------------------------------"
            tcp_packet = Ether(src =ip_mac.get(host_ip),dst = ip_mac.get("10.0.0.4"))/IP(src=host_ip,dst = "10.0.0.4",tos = 30)/UDP(sport = 100,dport = 100)
            sendp(tcp_packet)
            scale_flow(host_ip,ip_mac)
            sendp(Ether(src =ip_mac.get(host_ip),dst = ip_mac.get("10.0.0.4"))/IP(src=host_ip,dst = "10.0.0.4",tos = 40)/UDP(sport = 100,dport = 100))