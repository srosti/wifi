import multiprocessing
from scapy.all import *
 
from monitor_ifc import Monitor
 
class ConnectionPhase:
    """
    Establish a connection to the AP via the following commands
    """
 
    def __init__(self, monitor_ifc, sta_mac, bssid):
        self.state = "Not Connected"
        self.mon_ifc = monitor_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
 
    def send_authentication(self):
        """
        Send an Authentication Request and wait for the Authentication Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.
 
        :return: -
        """




#        param = Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
#        rates = Dot11Elt(ID='Rates', info="\x03\x12\x96\x18\x24\x30\x48\x60")
#        dsset = Dot11Elt(ID='DSset', info='\x01')
#        packet = Dot11(type=0, subtype=11, addr1=self.bssid, addr2=self.sta_mac,
#                      addr3=self.bssid) / param 



        pkt = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid) / Dot11Auth(
                algo=0, seqnum=0x0001, status=0x0000)

        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_auth,
            args=(result_queue, ))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(pkt, ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Authenticated"
 
    def send_assoc_request(self, ssid):
        """
        Send an Association Request and wait for the Association Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.
 
        :param ssid: Name of the SSID (ESSID)
        :return: -
        """
        if self.state != "Authenticated":
            print("Wrong connection state for Association Request: {0} "
                  "- should be Authenticated".format(self.state))
            return 1
 
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid) / Dot11AssoReq(
                cap=0x1100, listen_interval=0x00a) / Dot11Elt(
                    ID=0, info="{}".format(ssid))
        packet.show()
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_assoc_resp,
            args=(result_queue,))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet, "AssoReq", ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Associated"
    
    def send_deauth(self):
        """
        Send a Deauthentication packet. This will end the association with the AP
 
        :param ssid: Name of the SSID (ESSID)
        :return: -
        """

        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid) / Dot11Deauth()
         
        self.mon_ifc.send_packet(packet)

        print("Disassociated")
 
def main():
    monitor_ifc = "mon0"

    sta_mac = "00:02:6f:85:51:93"
    bssid = "00:30:44:16:7B:07"

    conf.iface = monitor_ifc
 
    # mac configuration per command line arguments, MACs are converted to
    # always use lowercase
    mon_ifc = Monitor(monitor_ifc, sta_mac.lower(), bssid.lower())
 
    connection = ConnectionPhase(mon_ifc, sta_mac, bssid)
    connection.send_authentication()
    if connection.state == "Authenticated":
        print("STA is authenticated to the AP!")
    else:
        print("STA is NOT authenticated to the AP!")
    connection.send_assoc_request(ssid="blah")
    if connection.state == "Associated":
        print("STA is connected to the AP!")
    else:
        print("STA is NOT connected to the AP!")
    
    connection.send_deauth()
 
if __name__ == "__main__":
    sys.exit(main())
