#!/usr/bin/env python

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import os as os
import binascii



packet=[]

rates_dict = [{
	'1' : '\x82',
	'2' : '\x84',
	'5.5' : '\x8b',
	'11' : '\x96',
	'6' : '\x0c',
	'9' : '\x12',
	'12' : '\x18',
	'18' : '\x24',
	'24' : '0',
	'36' :'H',
	'48' : '`',
	'54' : 'l'
	}, {
	'1' : '\x82',
	'2' : '\x84',
	'5.5' : '\x8b',
	'11' : '\x96',
	'6' : '\x8c',
	'9' : '\x12',
	'12' : '\x98',
	'18' : '\x24',
	'24' : '\xb0',
	'36' :'H',
	'48' : '`',
	'54' : 'l'
	}
]


# Extracted Packet Format 
Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 Subtype  : {}   
 Address 1  : {} | Address 2 : {} [BSSID] 
 Address 3  : {} | Address 4 : {} 
 AP   : {} [SSID]
"""

def PacketHandler(pkt, ssid=None):
	if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 8:
		current_ssid = pkt.payload.payload.payload.info
		rates = None
		extended_rates = None
		if 'AER2200-b06' in current_ssid:
			print("ssid = " + current_ssid)
#				import pdb; pdb.set_trace()
			packet = pkt
			get_rates(pkt)
			return False
		else:
			return False


def get_rates(pkt):
	radio_type = 1
	while pkt.payload:
		# Basic Rates layer is in ID=1
		if pkt.ID == 1:
			rates = pkt.info
		if pkt.ID == 50:
			radio_type = 0
			rates = rates + pkt.info
		pkt = pkt.payload

	# Check which rates are enabled
	for rate in rates:
		for index, byte in rates_dict[radio_type].iteritems():
			if byte == rate:
				print("rate = " + index)

def get_beacon(*args,  **kwargs):
	"""
	Function For Filtering Beacon Frames And Extract Access 
	Point Information From Captured Packets.
	"""

	# create monitor interface using iw
	cmd = '/sbin/iw dev %s interface add %s type monitor >/dev/null 2>&1' \
		% ("wlp3s0", "mon0")
	try:
		os.system(cmd)
	except:
		raise
	
#	scapy.sniff(prn=PacketHandler, *args, **kwargs)
	ssid = sys.argv[1]
	print("argv[1]=" + ssid)
#	ssid = 'AER2200-b06'
	scapy.sniff(stop_filter=PacketHandler, *args, **kwargs)
	return (packet)


if __name__=="__main__":

	packet = get_beacon(iface="mon0", timeout=60)


# int(binascii.hexlify('\x83'), 16)
