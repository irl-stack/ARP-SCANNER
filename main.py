# CODED BY IRL0
# FSOCIETY

import scapy.all as scapy
import threading
from queue import Queue
import time
from mac_vendor_lookup import MacLookup

# Function to perform ARP scan on a given IP
def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device)
    return devices

# Function to scan IP range using threading
def scan_range(ip_range):
    # List to store discovered devices
    discovered_devices = []
    
    def worker():
        while not ip_queue.empty():
            ip = ip_queue.get()
            devices = arp_scan(ip)
            if devices:
                for device in devices:
                    # Lookup MAC vendor
                    try:
                        mac_vendor = MacLookup().lookup(device["mac"])
                        device["vendor"] = mac_vendor
                    except Exception as e:
                        device["vendor"] = "Unknown"
                    discovered_devices.append(device)
                    print(f"IP: {device['ip']} - MAC: {device['mac']} - Vendor: {device['vendor']}")
            ip_queue.task_done()

    # Prepare the IPs in the range
    ip_queue = Queue()
    for ip in ip_range:
        ip_queue.put(ip)

    # Start worker threads
    num_threads = 50
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        threads.append(thread)
        thread.start()

    ip_queue.join()  # Wait for all threads to finish
    return discovered_devices

# Function to generate an IP range based on a network address and CIDR (e.g., 192.168.1.0/24)
def generate_ip_range(network):
    ip, cidr = network.split('/')
    cidr = int(cidr)
    ip_parts = ip.split('.')
    base_ip = '.'.join(ip_parts[:3])
    ip_range = [f"{base_ip}.{i}" for i in range(1, 255)]
    return ip_range

# Function to detect ARP spoofing (basic detection)
def detect_arp_spoofing(arp_results):
    seen_macs = {}
    duplicates = []

    for device in arp_results:
        ip = device['ip']
        mac = device['mac']
        if ip in seen_macs:
            if seen_macs[ip] != mac:
                duplicates.append((ip, seen_macs[ip], mac))
        else:
            seen_macs[ip] = mac

    if duplicates:
        print("\n[WARNING] Possible ARP Spoofing Detected:")
        for dup in duplicates:
            print(f"IP: {dup[0]} - MAC 1: {dup[1]} - MAC 2: {dup[2]}")
    else:
        print("\nNo ARP spoofing detected.")

# Main function to run the ARP scanner
if __name__ == "__main__":
    network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    ip_range = generate_ip_range(network)

    print(f"Scanning {network}... Please wait.\n")
    start_time = time.time()
    
    # Perform the scan
    results = scan_range(ip_range)

    # Detect ARP spoofing (optional)
    detect_arp_spoofing(results)
    
    print(f"\nScan completed in {round(time.time() - start_time, 2)} seconds.")
    print(f"Discovered {len(results)} devices.")
