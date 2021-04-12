from scapy.sendrecv import sniff
from scapy.all import *
from scapy.utils import wrpcap


dpkt = sniff(count=1000)


wrpcap("demo.pcap", dpkt)


print('xxx')
