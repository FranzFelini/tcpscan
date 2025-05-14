import os
import sys
import subprocess
from scapy.all import sniff, TCP, IP, get_if_list

if not hasattr(sys, 'real_prefix') and not hasattr(sys, 'base_prefix') and not sys.platform.startswith('linux'):
    if os.geteuid() != 0:
        sys.exit(1)

def list_interfaces():
    interfaces = get_if_list()
    if not interfaces:
        print("No network interfaces found.")
        sys.exit(1)
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    return interfaces

def is_interface_active(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface], text=True)
        return "status: active" in output
    except subprocess.CalledProcessError:
        print(f"Error checking status of interface {interface}.")
        return False

def is_wifi_interface(interface):
    try:
        airport_info = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
        return f"Hardware Port: Wi-Fi" in airport_info and f"Device: {interface}" in airport_info
    except subprocess.CalledProcessError:
        return False

def activate_interface(interface):
    if interface == "lo0":
        return True 
    if interface.startswith(("gif", "stf", "utun", "bridge")):
        print(f"Interface {interface} is a virtual interface and cannot be activated programmatically.")
        return False

    if is_wifi_interface(interface):
        try:
            subprocess.run(["networksetup", "-setairportpower", interface, "on"], check=True)
            print(f"Enabled Wi-Fi for {interface}. Checking status...")
            return is_interface_active(interface)
        except subprocess.CalledProcessError:
            print(f"Failed to enable Wi-Fi for {interface}.")
            return False

    try:
        output = subprocess.check_output(["ifconfig", interface], text=True)
        if "inet " not in output:
            print(f"Interface {interface} is likely an Ethernet interface. Please ensure an Ethernet cable is connected.")
            return False
        return is_interface_active(interface)
    except subprocess.CalledProcessError:
        print(f"Error checking {interface} configuration.")
        return False

def get_user_interface():
    interfaces = list_interfaces()
    while True:
        try:
            choice = input("Enter the number of the interface to capture packets: ")
            choice = int(choice)
            if 1 <= choice <= len(interfaces):
                selected = interfaces[choice - 1]
                print(f"Selected interface: {selected}")
                if is_interface_active(selected):
                    print(f"Interface {selected} is active.")
                    return selected
                else:
                    print(f"Interface {selected} is inactive.")
                    if activate_interface(selected):
                        print(f"Interface {selected} is now active.")
                        return selected
                    else:
                        print(f"Could not activate {selected}. Please select another interface or ensure it's connected (e.g., plug in an Ethernet cable for Ethernet interfaces).")
            else:
                print(f"Please enter a number between 1 and {len(interfaces)}.")
        except ValueError:
            print("Please enter a valid number.")

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        mss = "Not Present"
        for opt in packet[TCP].options:
            if opt[0] == 'MSS':
                mss = opt[1]
                break

        win = packet[TCP].window
        ack = "Yes" if packet[TCP].flags & 0x10 else "No"
        print(f"{src_ip} -> {dst_ip}, MSS: {mss}, Window: {win}, ACK: {ack}")

def main():
    print("TCP Packet Fingerprint Tool")
    selected_interface = get_user_interface()
    print(f"Capturing up to 10 TCP SYN packets on interface {selected_interface} (timeout: 10 seconds)...")
    try:
        packets = sniff(iface=selected_interface, filter="tcp[tcpflags] & tcp-syn != 0", count=10, timeout=10, prn=process_packet)
        if not packets:
            print("No TCP SYN packets captured. Ensure there is TCP handshake traffic on the interface (e.g., start a new connection).")
        else:
            print(f"Captured {len(packets)} TCP SYN packets.")
    except Exception as e:
        print(f"Error capturing packets: {e}")
        print("Ensure the interface is valid and you have sufficient permissions.")

if __name__ == "__main__":
    main()