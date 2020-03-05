#!/usr/bin/python3

from scapy.all import *
import pcapy
import argparse
import os
from base64 import b16decode

Protocols = ["HOPOPT", "ICMP", "IGMP", "GGP", "IPv4", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP",
"ARGUS", "EMCON", "XNET", "CHAOS", ]
count = 0


def packetcallback(packet):
  global count

  try:
    if packet[TCP].dport == 3389:
      count = count + 1
      print("ALERT #{}: RDP is detected from {} ({})!" .format(count, packet[IP].src, Protocols[packet.proto]))

    if packet[TCP].flags == "": #null scan
      count = count + 1
      print("ALERT #{}: Null scan is detected from {} ({})!" .format(count, packet[IP].src, Protocols[packet.proto]))
    
    if packet[TCP].flags == "F": # fin scan
      count = count + 1
      print("ALERT #{}: Fin scan is detected from {} ({})!" .format(count, packet[IP].src, Protocols[packet.proto]))

    if packet[TCP].flags == "FPU": # xmas scan
      count = count + 1
      print("ALERT #{}: Xmas scan is detected from {} ({})!" .format(count, packet[IP].src, Protocols[packet.proto]))
    

    packet_data_raw = str(packet)      
    if "nikto" in packet_data_raw.lower(): # Nikto scan
      count = count + 1
      print("ALERT #{}: Nikto scan is detected from {} ({})!" .format(count, packet[IP].src, Protocols[packet.proto]))
    

  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)

    #capture passwords and username
    passuser = os.popen('ettercap -T -r ' + args.pcapfile + ' | grep \"PASS:\"').read()

    count = count + 1
    print("ALERT #{}: Password and username detected {}" .format(count,passuser))

  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
