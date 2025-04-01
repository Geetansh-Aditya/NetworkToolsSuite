#!/usr/bin/env python3

import argparse
import ipaddress
import re
import sys
import os
from scapy.all import ARP, Ether, srp, get_if_list
from tabulate import tabulate

def valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {ip}")

def valid_subnet(subnet):
    try:
        ipaddress.IPv4Network(subnet, strict=False)
        return subnet
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid subnet: {subnet}")

def arp_scan(targets, interface=None, timeout=2, verbose=False):
    results = {}
    packets = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=targets)
    
    if verbose:
        print(f"\n[*] Scanning {len(targets)} targets")
        if interface:
            print(f"[*] Using interface: {interface}")
        print(f"[*] Timeout set to {timeout} seconds")

    try:
        ans, _ = srp(packets, iface=interface, timeout=timeout, verbose=0, inter=0.1)
    except Exception as e:
        print(f"\n[!] Error sending packets: {e}")
        return results

    for sent, received in ans:
        results[received.psrc] = received.hwsrc

    return results

def get_mac(targets, interface=None, timeout=2, verbose=False):
    if isinstance(targets, str):
        targets = [targets]
    return arp_scan(targets, interface, timeout, verbose)

def main():
    if os.geteuid() != 0:
        print("\n[!] This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Advanced ARP Network Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", nargs='+', type=valid_ip,
                      help="Single or multiple IP addresses to scan")
    group.add_argument("-s", "--subnet", type=valid_subnet,
                      help="Subnet to scan (e.g., 192.168.1.0/24)")
    
    parser.add_argument("-I", "--interface",
                       help="Network interface to use")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                       help="Timeout in seconds for ARP response")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("-o", "--output", choices=['table', 'list', 'csv'], default='table',
                       help="Output format")
    
    args = parser.parse_args()

    if args.interface and args.interface not in get_if_list():
        print(f"\n[!] Interface {args.interface} not found!")
        print(f"Available interfaces: {', '.join(get_if_list())}")
        sys.exit(1)

    results = {}
    found = False

    if args.ip:
        results = get_mac(args.ip, args.interface, args.timeout, args.verbose)
        found = bool(results)
    elif args.subnet:
        subnet = ipaddress.IPv4Network(args.subnet)
        targets = [str(ip) for ip in subnet.hosts()]
        results = arp_scan(targets, args.interface, args.timeout, args.verbose)
        found = bool(results)

    if not found:
        print("\n[-] No results found")
        sys.exit(1)

    if args.output == 'table':
        headers = ["IP Address", "MAC Address"]
        data = [[ip, mac] for ip, mac in results.items()]
        print("\n" + tabulate(data, headers=headers, tablefmt="grid"))
    elif args.output == 'list':
        for ip, mac in results.items():
            print(f"{ip}\t{mac}")
    elif args.output == 'csv':
        print("IP Address,MAC Address")
        for ip, mac in results.items():
            print(f"{ip},{mac}")

if __name__ == "__main__":
    main()