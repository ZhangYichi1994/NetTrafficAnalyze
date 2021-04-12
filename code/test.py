from scapy.all import *
for i in range(100):
    data = 'hello,word!'
    pkt = IP(src='192.168.1.215', dst='192.168.1.158') / TCP(sport=12345, dport=12345) / data
    send(pkt, inter=1, count=5)  # 每隔一秒发包，发5次
print('xxx')
