from scapy.all import * # python library for network packet manipulation

def packet_callback(packet):  # function that processes each captured packet
	if packet.haslayer(IP):   # filters packets to only process those containing an IP layer

		src_ip = packet[IP].src
		dst_ip = packet[IP].dst
		proto = packet[IP].proto

		print(f"[+] IP Packet: {src_ip} -> {dst_ip} | Proto: {proto}")

		if packet.haslayer(TCP):  # if packet contains TCP layer, prints source port, and dest port

			print(f"	TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
		elif packet.haslayer(UDP):
			print(f"	UDP Port: {packet[UDP].dport}")

# Starting sniffing (stop after 10 packets)
sniff(prn=packet_callback, count=10) # specify call back function

