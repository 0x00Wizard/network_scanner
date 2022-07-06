#!/usr/bin/env python
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print("IP \t\t\tMAC Address \n------------------------------------")
    client_list = []

    for data in answered_list:
        print(f"{data[1].psrc} \t\t {data[1].hwsrc}")
        print("-" * 30)


scan("192.168.3.1/24")
