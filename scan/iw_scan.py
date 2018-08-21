import subprocess
import re
import time

class iwScanParser:
    """
    Class for scanning the iw scan command output
    """

    def __init__(self, dev=None, ssid=None, timeout=5):
        """
        Initialization
        Optional: ssid and timeout in seconds to look for
        """
        self.dev = dev
        self.ssid = ssid
        self.bssid_dict = dict()
        self.rates_dict = dict()
        self.data = None

        if self.ssid:
            self.wait_for_ssid(ssid, timeout)
        else:
            self.scan()
            self.parse(self.data[0])
    
    def scan(self):
        """
        Run "iw <dev> scan" command on the shell 
        Currently only retrive BSSID, SSID and suppported rates. Future enhancements
        to get more beacon frame information can be added later.
        """
        p = subprocess.Popen(
            'sudo iw {0} scan | egrep \'^BSS |SSID: |Supported rates: \''.format(
            self.dev), shell=True, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.data = p.communicate()
    
    def wait_for_ssid(self, ssid=None, timeout=None):
        start_time = time.time()
        duration = 0
        if ssid:
            while (ssid not in self.bssid_dict) and (duration < timeout):
                self.scan()
                self.parse(self.data[0])
                duration = time.time() - start_time

    def parse(self, scan_results):
        """
        Parse the raw data from iw returned to stdout
        """
        scan = scan_results.splitlines()
        x = 0
        bssid = None
        ssid = None
        while x < len(scan):
            scan[x] = scan[x].lstrip()
            if b'BSS' in scan[x]:
                bssid = scan[x].lstrip(b'BSS ')[0:17]
            if b'SSID:' in scan[x]:
                ssid = scan[x].lstrip(b'SSID: ')
                self.bssid_dict.update([(ssid, bssid)])
            if b'Supported rates:' in scan[x]:
                rates = scan[x].lstrip(b'Supported rates:')
                rates = re.sub('[*]', '', rates)
                rates_list = map(float, rates.split())
                self.rates_dict.update([(ssid, rates_list)])
            x += 1

    def get_rates(self, ssid=None):
        """
        Return a list of supported rates given an ssid
        """
        if ssid in self.rates_dict: 
            return self.rates_dict[ssid]
        if self.ssid in self.rates_dict: 
            return self.rates_dict[self.ssid]
        return None
    
    def get_bssid(self, ssid=None):
        """
        Return a list of supported rates given an ssid
        """
        if ssid in self.bssid_dict: 
            return self.bssid_dict[ssid]
        if self.ssid in self.bssid_dict: 
            return self.bssid_dict[self.ssid]
        return None


iw = iwScanParser('wlp3s0', 'blah')
rates = iw.get_rates()
bssid = iw.get_bssid()
iw = iwScanParser('wlp3s0', 'CP-Guest', 10)
rates = iw.get_rates()
bssid = iw.get_bssid()
iw = iwScanParser('wlp3s0')
rates = iw.get_rates('CP-Guest')
bssid = iw.get_bssid('CP-Guest')
print("CP-Guest: bssid={} supported rates={}".format(bssid, rates))
