import socket as sock
rawSocket = sock.socket(sock.AF_PACKET, sock.SOCK_RAW, sock.htons(0x0003))
rawSocket.bind(("mon0", 0x0003))
ap_list = set()
while True:
    pkt = rawSocket.recvfrom(2048)[0] 
    if pkt[26] == "\x80":
        if pkt[36:42] not in ap_list  and ord(pkt[63]) > 0:
            ap_list.add(pkt[36:42])
            print("SSID: {}  BSSID: {}".format(pkt[64:64 +ord(pkt[63])], pkt[36:42].encode('hex')))


