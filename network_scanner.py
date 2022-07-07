#!/usr/bin/env python
import scapy.all as scapy
import optparse
import requests


MAC_ADDRESS_ENDPOINT = "https://api.macaddress.io/v1?"


def mac_address_lookup(mac):
    params = {
        "apiKey": "at_fkqRppKrlTqskY1pMN1wBHVuTnMyR",
        "search": mac,
        "output": "json"
    }

    response = requests.get(url=MAC_ADDRESS_ENDPOINT, params=params)
    data = response.json()["vendorDetails"]["companyName"]

    return data


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="example: python3 network_scanner.py --t 10.0.2.1/24")
    options, args = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []

    for data in answered_list:
        client_dict = {"ip": data[1].psrc, "mac": data[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_results(results_list):
    print("IP \t\t\tMAC Address \t\t\t CompanyName\n")
    print("-" * 70)
    for client in results_list:
        print(f"{client['ip']} \t\t {client['mac']} \t\t {mac_address_lookup(client['mac'])}")


option = get_arguments()
scan_result = scan(option.target)
print_results(scan_result)
