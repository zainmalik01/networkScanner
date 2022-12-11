#!/usr/bin/env python

import scapy.all as scapy
import argparse

def getArgumnents():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP/ IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broad_req = broadcast/arp_request
    answered_list = scapy.srp(arp_broad_req,timeout=1,verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict={"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
        # print(element[1].psrc+"\t\t"+element[1].hwsrc)
    return clients_list

def print_result(results_list):
    print("IP Address\t\tMac Address\n.........................................")
    for element in results_list:
        print(element['ip']+"\t\t"+element['mac'])

options=getArgumnents()
result=scan(options.target)
print_result(result)