import sys 
import scapy.all as scapy
import os 


def help(): #prints the usage of the tool.
    usage ="""
    python net_recon.py -i --iface interface_name
    python net_recon.py -p --passive 
    python net_recon.py -a --active
"""
    print(f'Usage: {usage}')
    sys.exit(1)


def passive_scan(interface,ips,macs,pktsenders,activitys):
    """This Function finds IP address and mac address by sniffing the network."""
    t = scapy.AsyncSniffer(iface = interface,filter='arp',count=5)
    t.start()
    t.join()
    pkts = t.results
    for pkt in pkts:
        count_packet_observed(pkt.pdst,pktsenders,activitys)
        if pkt.op == 2:
            if pkt.hwdst not in macs:
                ips.append(pkt.pdst)
                macs.append(pkt.hwdst)

def count_packet_observed(ip,pktsenders,activitys):
    """This function counts host activity for each IP."""
    if ip in pktsenders:
        for i in range(len(pktsenders)):
            if pktsenders[i]==ip:
                activitys[i] +=1
    else:
        pktsenders.append(ip)
        activitys.append(1)



def active_recon(interface):
    """This function finds the active IP address by pinging all hosts."""
    active_ips=[]
    my_ip = scapy.get_if_addr(interface) # fetches the IP address for the given network interface.
    TIMEOUT = 2
    gw = scapy.conf.route.route("0.0.0.0")[2] # finds gateway address
    gw = str(gw[:(len(gw)-1)])
    for ip in range(0, 256): # this is assumed to be a /24 mesh
        packet = scapy.IP(dst=gw + str(ip),src=my_ip, ttl=20)/scapy.ICMP()
        reply = scapy.sr1(packet, timeout=TIMEOUT,verbose=True)
        if not (reply is None):
            active_ips.append(reply.src)
    return active_ips


def print_screen(interface,mode,hosts,ips,macs=['?'],pktsenders=[0],activitys=[0]):
    """this function measures the size of the Terminal and prints the values to the screen"""
    os.system('cls' if os.name == 'nt' else 'clear') # clears the terminal 
    rows, columns = os.popen('stty size', 'r').read().split() # measures the size of the Terminal
    interface = "interface:"+interface
    mode = "Mode:"+mode
    hosts = "Found " + str(hosts) + " Hosts"
    middle = int((int(columns) - len(mode)) / 2) 
    right = (int(columns) - 17) - (middle + len(interface)) 
    print(interface+(" "* (middle- len(interface)))+mode+(" " * (right- len(mode)))+hosts)
    print("-"*int(columns))
    print("MAC"+(" "* middle)+"IP"+(" "*right)+"Host Activity")
    print("-"*int(columns))
    if len(macs)==1 and macs[0] == '?':
        for i in range(len(ips)):
            print(macs[0]+(" "*(middle-1))+ips[i])
    else:
        count = 0
        for i in range(len(ips)):
            if ips[i] in pktsenders:
                for j in range(len(pktsenders)):
                    if pktsenders[j] == ips[i]:
                        count = activitys[j]
            print(macs[i]+(" "*(middle-17))+ips[i]+(" "*right)+str(count))
    

def main():
    """main function that takes the arguments and executes the correct functions"""
    if len(sys.argv) != 4:
        help()

    else: 
        tmp = sys.argv[1:]
        if str(tmp[0].lower())=="-i" or str(tmp[0].lower())=="--iface":
            interface = tmp[1]

            if str(tmp[2].lower())=="-p" or str(tmp[2].lower())=="--passive":
                ips=[]
                macs = []
                pktsenders = [] 
                activitys= []
                try:
                    while True:
                        passive_scan(interface,ips,macs,pktsenders,activitys)
                        print_screen(interface,"Passive",len(ips),ips,macs,pktsenders,activitys)
                    
                except KeyboardInterrupt:
                    print("You pressed CTRL + C")
                    print("Program interrupted.")
                    os._exit


            elif str(tmp[2].lower())=="-a" or str(tmp[2].lower())=="--active":
                print("Active Mode running...\nPinging all hosts on the network")
                active_ips = active_recon(interface)
                print_screen(interface,"Active",len(active_ips),active_ips)

            else:
                help()

        else:
            help()


if __name__=='__main__':
    main()
