## DESCRIPTION:
It provides user the option to analyze a live stream of network packets or a set of PCAPs for incidents. Your tool shall be able to analyze for the following incidents:

  * NULL scan
  . FIN scan
  . Xmas scan
  . Nikto scan
  . Someone scanning for Remote Desktop Protocol (RDP)
  
## HOW IT WORKS:

If an incident is detected, alert will be displayed in the following format:

ALERT #{incident_number}: #{incident} is detected from #{source IP address} (#{protocol or port number}) (#{payload})!

Example outputs: ALERT #1: Xmas scan is detected from 1.1.1.1 (TCP)! 
                ALERT #2: Null scan is detected from 1.2.3.4 (TCP)!


## REQUIREMENTS:

  1. you need python3
  2. you need pcapy module
  3. you must log in as root or admin depending on your OS


## HOW TO USE IT:

run the following command:
  python3 alarm.py

By default with no arguments, the tool will sniff on network interface eth0. The tool must handle three command line arguments:

-i INTERFACE: Sniff on a specified network interface -r PCAPFILE: Read in a PCAP file -h: Display message on how to use tool

Example 1: python alarm.py -h shall display something of the like:

`usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]

A network sniffer that identifies basic vulnerabilities

optional arguments: -h, --help show this help message and exit -i INTERFACE Network interface to sniff on -r PCAPFILE A PCAP file to read`

Example 2: python3 alarm.py -r set2.pcap will read the packets from set2.pcap

Example 3: python3 alarm.py -i en0 will sniff packets on a wireless interface en0

When sniffing on a live interface, the tool will keep running. To quit it, press Control-C

