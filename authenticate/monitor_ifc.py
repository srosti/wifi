from scapy.all import *
 
class Dot11EltRates(Packet):
    """
    Our own definition for the supported rates field
    """
    name = "802.11 Rates Information Element"
    # Our Test AP has the rates 6, 9, 12 (B), 18, 24, 36, 48 and 54, with 12
    # Mbps as the basic rate - which does not have to concern us.
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    #supported_rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    #supported_rates = [0x82]
 
    fields_desc = [
        ByteField("ID", 1),
        ByteField("len", len(supported_rates))
        ]
 
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(
            index + 1), rate))
 
class Monitor:
    def __init__(self, mon_ifc, sta_mac, bssid):
        """
 
        :param mon_ifc: WLAN interface to use as a monitor
        :param channel: Channel to operate on
        :param sta_mac: MAC address of the STA
        :param bssid: BSSID of the AP to attack
        """
        self.mon_ifc = mon_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
        self.auth_found = False
        self.assoc_found = False
        self.dot11_rates = Dot11EltRates()

 
    def send_packet(self, packet, packet_type=None):
        """
        Send and display a packet.
 
        :param packet_type: Specific types require
        :param packet:
        :return:
        """

        print("send_packet()")

        # Send out the packet
        if packet_type is None:
            send(packet)
        elif packet_type == "AssoReq":
            packet /= self.dot11_rates
            send(packet)
        else:
            print("Packet Type '{0}' unknown".format(packet_type))
 
    def check_auth(self, packet):
        """
        Try to find the Authentication from the AP
 
        :param packet: sniffed packet to check for matching authentication
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3

        print("check_auth")

        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.auth_found = True
            print("Detected Authentication from Source {0}".format(
                seen_bssid))
        print("auth_found={}".format(self.auth_found))
        return self.auth_found
 
    def check_assoc(self, packet):
        """
        Try to find the Association Response from the AP
 
        :param packet: sniffed packet to check for matching association
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
        
        print("check_assoc")
 
        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.assoc_found = True
            print("Detected Association Response from Source {0}".format(
                seen_bssid))
        return self.assoc_found
 
    def search_auth(self, mp_queue):
        print("\nScanning max 5 seconds for Authentication "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11Auth),
              stop_filter=self.check_auth,
              timeout=10)
        mp_queue.put(self.auth_found)
 
    def search_assoc_resp(self, mp_queue):
        
        print("\nScanning max 5 seconds for Association Response "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11AssoResp),
              stop_filter=self.check_assoc,
              timeout=10)
        mp_queue.put(self.assoc_found)

