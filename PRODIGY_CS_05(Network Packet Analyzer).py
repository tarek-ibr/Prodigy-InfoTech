from scapy.all import *
import netifaces


# Function to analyze packets
def packet_analyze(packet):

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        if TCP in packet:
            # TCP packet
            dport = packet[TCP].dport
            sizePayload = len(packet[TCP].payload)
            print(f"TCP  -> from IP = {source_ip}:{packet[TCP].sport} To IP = {destination_ip}:{dport}   size: {sizePayload} bytes AND the Packet is \n{packet[TCP].payload}\n")
        
        elif UDP in packet:
            # UDP packet
            dport = packet[UDP].dport
            sizePayload = len(packet[UDP].payload)
            print(f"UDP  -> from IP = {source_ip}:{packet[UDP].sport} To IP = {destination_ip}:{dport}   size: {sizePayload} bytes AND the Packet is \n{packet[UDP].payload}\n")
        
        else:
            # IP packet without TCP or UDP
            print(f"IP -> from IP = {source_ip} To IP = {destination_ip}")

# Get the list of network interfaces
NET = netifaces.interfaces()

# Print the list of available interfaces
for i in NET:
    if i != 'lo': 
        print(i)

# User input for the interface to analyze
ifaceName = input("what is the Interface You want to analyze ENTER THE EXACT NAME:\n")

# Check if the entered interface exists
if ifaceName in NET:
    print(" packet sniffer ")
    # Sniff packets on the specified interface and call the 'packet_analyze' function
    sniff(iface=ifaceName, prn=packet_analyze)
else:
    print("the Interface is not found")
