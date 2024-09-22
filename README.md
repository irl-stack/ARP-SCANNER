# CODED BY IRL0
# FSOCIETY
---------------------------------------------------

# WHAT IS AN ARP SCANNER

An ARP scanner is a tool that scans a local network to discover devices by sending ARP (Address Resolution Protocol) requests and analyzing the responses. It's used to map IP addresses to their corresponding MAC addresses and identify the devices connected to a network.

What is ARP (Address Resolution Protocol)?
ARP is a protocol used in computer networks to map an IP address (Layer 3 - Network Layer) to a MAC address (Layer 2 - Data Link Layer). This is essential for communication between devices within the same local network.

When a device wants to communicate with another device on the local network, it uses ARP to find out the MAC address corresponding to the target device's IP address. If it doesn't know the MAC address, it sends out an ARP request.

The device with the matching IP address responds with an ARP reply that contains its MAC address.

How ARP Scanners Work:
An ARP scanner automates the process of sending ARP requests to all IP addresses within a specified range or subnet, collects the responses, and then provides a list of active devices on the network along with their corresponding MAC addresses.

Here’s what an ARP scanner typically does:

Sends ARP requests: The ARP scanner broadcasts ARP requests to every IP address in a specified network range (e.g., 192.168.1.1 to 192.168.1.254).

Receives ARP replies: Devices on the network respond to the ARP request with their MAC addresses if they are active.

Maps IPs to MACs: The scanner collects the IP addresses and their corresponding MAC addresses from the ARP replies.

Lists devices: It presents a list of discovered devices, showing the IP address, MAC address, and sometimes additional details like the vendor of the network device (based on the MAC address).

Why Use an ARP Scanner?
Network Discovery: It helps network administrators discover devices connected to the local network, such as computers, routers, printers, smartphones, etc.

Security Monitoring: An ARP scanner can help detect unauthorized devices on a network. If a device is found that shouldn't be on the network, it could indicate a potential security threat.

Troubleshooting: ARP scanners are useful for troubleshooting network issues, especially when certain devices are unreachable, or IP address conflicts occur.

Detecting ARP Spoofing: ARP scanners can be used to detect ARP spoofing attacks. In such attacks, a malicious device tries to intercept traffic by pretending to have the same IP address as another device on the network.

Example of ARP Scanner Usage:
You might use an ARP scanner to scan your home or office network to find out what devices are connected to it. The result could be something like this:
IP Address	MAC Address	Vendor
192.168.1.1	00:1A:2B:3C:4D:5E	Cisco
192.168.1.5	00:1B:3C:4D:5E:6F	Apple
192.168.1.10	00:1C:4D:5E:6F:7G	Dell
This table shows which devices are connected to the network, their MAC addresses, and possibly their vendor (if the MAC address is looked up). This information helps you identify the devices in your network and ensure no unknown or suspicious devices are connected.

Tools for ARP Scanning:
Nmap: Popular network scanner with ARP scanning functionality.
Scapy (Python): Allows building custom ARP scanning scripts.
Netdiscover: Lightweight ARP scanner often used in penetration testing.
Limitations of ARP Scanning:
ARP scanning works only within a local network (LAN), as ARP is limited to communication within the same subnet. It won't work over the internet or across different networks without a gateway.

Devices with firewalls or those set to ignore ARP requests may not respond, making them invisible to the scanner.
