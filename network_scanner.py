#!/usr/bin/env python
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    scapy.ls(broadcast)


scan("192.168.0.1")
