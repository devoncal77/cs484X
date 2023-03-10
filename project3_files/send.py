#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import ARP, IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in ifs:
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    # The type argument is either IP or ARP - the ARP destination is used to generate an ARP request
    if len(sys.argv)<4:
        print('pass 3 arguments: <type> <destination> "<message>"')
        exit(1)

    req_type = sys.argv[1]
    addr = socket.gethostbyname(sys.argv[2])
    iface = get_if()

    if req_type.upper() == "IP":
        print("sending on interface %s to %s" % (iface, str(addr)))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    elif req_type.upper() == "ARP":
        print("sending ARP request on interface %s for target IP %s" % (iface, str(addr)))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / ARP(pdst=addr)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    else:
        print('Invalid request type, please pass 3 arguments: <type> <destination> "<message>", where type is either IP or ARP')
        exit(1)

if __name__ == '__main__':
    main()
