#!/usr/bin/env python

from scapy.all import *

ap_list = []

def PacketHandler(pkt) :

    if pkt.haslayer(Dot11) :
        if pkt.type == 0 and pkt.subtype == 8 :
            if pkt.addr2 not in ap_list :
                ap_list.append(pkt.addr2)
                print('Found ssid={}'.format(pkt[Dot11Elt:1].info))
                if pkt[Dot11Elt:1].info == b'AER2100':
                    import pdb; pdb.set_trace()
                    # Channel 48 = b'\x00\x01\x00\x00'
                    channel = int( ord(pkt[Dot11Elt:3].info))
                    print("AP MAC: %s with SSID: %s using channel: %s" %(pkt.addr2, pkt.info, int( ord(pkt[Dot11Elt:3].info))))


sniff(iface="mon0", prn = PacketHandler)
