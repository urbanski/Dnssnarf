from scapy import *

def dns_callback(pkt):
   if DNS in pkt and pkt[UDP].dport == 53:
		print pkt.sprintf("client %IP.src%#%UDP.sport%: query: ") + \
			pkt[DNSQR].qname + " " +  pkt[DNSQR].sprintf("%qclass% %qtype% +")

iface = (sys.argv[1] if (len(sys.argv) > 1) else 'eth0')
sniff(iface=iface, prn=dns_callback, filter="udp and port 53", store=0)
