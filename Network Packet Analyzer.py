from scapy.all import *
import netifaces

# Function to analyze packets
def analyzer(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            # TCP packet
            dport = packet[TCP].dport
            payload_size = len(packet[TCP].payload)
            print(f"TCP  -> from IP = {ip_src}:{packet[TCP].sport} To IP = {ip_dst}:{dport}   size: {payload_size} bytes AND the Packet is \n{packet[TCP].payload}\n")
        
        elif UDP in packet:
            # UDP packet
            dport = packet[UDP].dport
            payload_size = len(packet[UDP].payload)
            print(f"UDP  -> from IP = {ip_src}:{packet[UDP].sport} To IP = {ip_dst}:{dport}   size: {payload_size} bytes AND the Packet is \n{packet[UDP].payload}\n")
        
        else:
            # IP packet without TCP or UDP
            print(f"IP -> from IP = {ip_src} To IP = {ip_dst}")

# Get the list of network interfaces
NET = netifaces.interfaces()

# Print the list of available interfaces
for i in NET:
    if i != 'lo': 
        print(i)

# User input for the interface to analyze
ifaceName = input("Enter the Interface You want to analyze **Note** THE EXACT NAME:\n")

# Check if the entered interface exists
if ifaceName in NET:
    print("^_^ packet sniffer ^_^")
    # Sniff packets on the specified interface and call the 'analyzer' function
    sniff(iface=ifaceName, prn=analyzer)
else:
    print("IFACE NOT FOUND TRY AGAIN")
