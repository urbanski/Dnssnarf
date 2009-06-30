#!/usr/bin/python
from scapy import *
import time

def dns_callback(pkt):
  if DNSQR in pkt and pkt.dport == 53:
    print str(time.asctime( time.localtime(time.time()) )) + \
      " session-id: " + str(pkt[DNS].id) + \
      " UDP client: " + pkt[IP].src + ":" + str(pkt.sport) + \
      " server: " + pkt[IP].dst + ":" + str(pkt.dport) + \
      " query: " + pkt[DNSQR].qname + \
      " class: " + pkt[DNSQR].sprintf("%qclass%") + \
      " type: " + pkt[DNSQR].sprintf("%qtype%")
  elif DNSRR in pkt and pkt.sport == 53:
    print str(time.asctime( time.localtime(time.time()) )) + \
      " session-id: " + str(pkt[DNS].id) + \
      " UDP server: " + str(pkt[IP].src) + ":" + str(pkt.sport) + \
      " response: " + pkt[DNSRR].rdata + \
      " class: " + pkt[DNSRR].sprintf("%rclass%") + \
      " type: " + pkt[DNSRR].sprintf("%type%") + \
      " ttl: " + str(pkt[DNSRR].ttl) + \
      " len: " + str(pkt[DNSRR].rdlen) 

sniff(prn=dns_callback, filter="udp and port 53", store=0)
