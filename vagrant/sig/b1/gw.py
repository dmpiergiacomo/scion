#!/usr/bin/python3
# Copyright 2016 ETH Zurich
# All rights reserved.



"""

This is a gateway application to make possible the connection between SCION and the legacy Internet.
On the outgoing interface, it takes IP packets and encapsulates them into SCION packets, while in the incoming
interface it takes SCION packets and convert them back into IP ones.

"""

# Stdlib
import getopt
import io
import socket
import sys
from struct import *

import pcapy

# SCION
from endhost.sciond import SCIONDaemon
from infrastructure.scion_elem import SCIONElement
from lib.defines import GEN_PATH
from lib.packet.host_addr import *
from lib.packet.scion_addr import (
    ISD_AS,
    SCIONAddr)
from lib.sciond_api import *
from lib.socket import ReliableSocket

# GW has two interfaces and is running on localhost
ETH_LEGACY_IP = 'enp0s9'
LEGACY_IP = '169.254.1.1'
ETH_SCION = 'enp0s8'
SCION_IP = '169.254.0.1'
SCION_PCK_LEN = 2**7 # can be between 0 and 2^16-1, I kept it small to speed up the tests
API_TOUT = 15

class ScionSIG(SCIONElement):
    """
    Class that implements a SCION-IP Gateway
    """
    NAME = ''

    def __init__(self, sig_host, sig_port, conf_dir, sig_isd, sig_as):
        """
        Create a SIG to handle the incoming and outgoing packets and that takes care of the encapsulation process
        """
        self.sig_host = sig_host
        self.sig_port = sig_port
        self.conf_dir = conf_dir
        self.sig_isd = sig_isd
        self.sig_as = sig_as
        self._req_id = 0
        sn = 0
        index = 0
        unused = 0

        super().__init__('sig', self.conf_dir, host_addr=sig_host, port=self.sig_port)

        print ('Starting GW...')
        print ('The legacy IP interface is ', ETH_LEGACY_IP, ' and the SCION interface is ', ETH_SCION)
        print('sys.path : ', sys.path)


        '''
            open device
            # Arguments here are:
            #   device
            #   snaplen (maximum number of bytes to capture _per_packet_)
            #   promiscious mode (1 for true)
            #   timeout (in milliseconds)
        '''
        cap = pcapy.open_live(ETH_LEGACY_IP, 65536, 1, 0)

        # start SCION Daemon
        sig_ia = ISD_AS().from_values(self.sig_isd, self.sig_as)
        sig_addr = SCIONAddr().from_values(sig_ia, self.sig_host)
        sd = start_sciond(self.conf_dir, sig_addr)

        # set up ReliableSocket to Dispatcher
        ### ADD SVC VALUE FOR THE SIG SERVICE; ADD THE SIG (IP & PORT) IN THE TOPOLOGY FILE !!!
        self._udp_sock = ReliableSocket(reg=(sig_addr, self.sig_port, None, None))
        self._socks.add(self._udp_sock, self.handle_accept) # SOBSTITUTE THE CALLBACK WITH SELF.ENCAP_ACCEPT !!!

        # create byte stream
        # IN THE FUTURE THERE MUST BE A STREAM FOR EACH REMOTE AS
        self.buf = io.BufferedRandom(io.BytesIO())


        # start sniffing packets
        while (1):
            (header, packet) = cap.next()
            # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            # return an ip packet
            parsed = (ip_pck, dest_ip) = self.parse_packet(packet)

            # iterate only if IP pck
            if all(parsed):
                # get destination AS by SIG's list
                # THIS SELECTION MUST BE BETTER DESIGNED (PROBABLY USING THE PySubnetTree)
                if dest_ip =='169.254.1.2':
                    dest_isd = 1
                    dest_as = 11
                if dest_ip =='169.254.2.2':
                    dest_isd = 1
                    dest_as = 12

                if dest_ip =='169.254.1.1':
                    dest_isd = 1
                    dest_as = 11

                dest_ia = ISD_AS().from_values(dest_isd, dest_as)
                paths = sd.get_paths(dest_ia)

                print(*paths, sep='\n')




                # *********************************************
                dest_ia = ISD_AS().from_values(dest_isd, dest_as)
                dest_host = HostAddrIPv4(dest_ip)
                sig_addr = SCIONAddr().from_values(dest_ia, dest_host)
                response = self._try_sciond_api(self._req_id, sig_addr.isd_as)
                print(*response, sep='\n')
                # *********************************************





                if paths:
                    print(*paths, sep='\n')

                    # add IP pck to stream
                    self.add_to_stream(sn, index, unused, ip_pck)
                    curr_pos = self.buf.tell()

                    # update index
                    if curr_pos >= SCION_PCK_LEN:
                        index = curr_pos % SCION_PCK_LEN

                    # Increment Sequence Number if sn >= 2^32-1
                    if sn < 4294967295:
                        sn = sn + 1
                    else:
                        sn = 0

                else:
                    print('Unable to get path directly from sciond')

            if curr_pos >= SCION_PCK_LEN:
                # forward first SCION pck in the stream if present
                self.forward(dest)



    def _try_sciond_api(self, isd_as):
        sock = ReliableSocket()
        request = SCIONDPathRequest.from_values(self._req_id, isd_as)
        packed = request.pack_full()
        self._req_id += 1
        start = time.time()
        try:
            sock.connect(self.api_addr)
        except OSError as e:
            logging.critical("Error connecting to sciond: %s", e)
            kill_self()
        while time.time() - start < API_TOUT:
            logging.debug("Sending path request to local API at %s: %s",
                          self.api_addr, request)
            sock.send(packed)
            data = sock.recv()[0]
            if data:
                response = parse_sciond_msg(data)
                if response.MSG_TYPE != SMT.PATH_REPLY:
                    logging.error("Unexpected SCIOND msg type received: %s" %
                                  response.NAME)
                    continue
                if response.p.errorCode != SCIONDPathReplyError.OK:
                    logging.error(
                        "SCIOND returned an error (code=%d): %s" %
                        (response.p.errorCode,
                         SCIONDPathReplyError.describe(response.p.errorCode)))
                    continue
                sock.close()
                return response
            logging.debug("Empty response from local api.")
        logging.critical("Unable to get path from local api.")
        sock.close()
        kill_self()


    # convert a string of 6 characters of ethernet address into a dash separated hex string
    def eth_addr(self, a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
        return b


    # function to parse a packet
    def parse_packet(self, packet):
        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        # Parse IP packets, IP Protocol number = 8 (0x0800)
        if eth_protocol == 8:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = packet[eth_length:20 + eth_length]

            # now unpack them :)
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            # analyze only incoming packets
            if d_addr == LEGACY_IP:
                print ('Destination MAC : ', self.eth_addr(packet[0:6]), ' Source MAC : ', self.eth_addr(packet[6:12]),
                       ' Protocol : ', str(eth_protocol))
                print ('Version : ', str(version), ' IP Header Length : ', str(ihl), ' TTL : ', str(ttl),
                       ' Protocol : ', str(protocol), ' Source Address : ', str(s_addr), ' Destination Address : ',
                       str(d_addr))

            return (packet[eth_length:], str(d_addr))


        # Parse ARP packets, ARP Protocol number = 1544 (0x0806)
        elif eth_protocol == 1544:
            # do nothing for now.....
            print('### ARP packet ###')
            return (None, None)

        return (None, None)


    def add_to_stream(self, sn, index, unused, ip_pck):
        format = '!IHH%ss' % (len(ip_pck))
        new_ip_pck = pack(format, sn, index, unused, ip_pck)
        self.buf.write(new_ip_pck)


    def forward(self):
        scion_pck = self.buf.read(SCION_PCK_LEN)
        self._udp_sock.send(scion_pck, )
        print ('forward method')


# start the SCION daemon
def start_sciond(conf_dir, addr, api=False, port=0, api_addr=None):
    return SCIONDaemon.start(conf_dir, addr.host, api_addr=api_addr, run_local_api=api, port=port)


def main(argv):
    """
    Parse the command-line arguments and start the SCION GW.
    """
    try:
        opts, args = getopt.getopt(argv, "ha:p:d:s:", ["address=", "port=", "isd=", "as="])
    except getopt.GetoptError:
        print ('test.py -a <address> -p <port> -d <isd> -s <as>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('test.py -a <address> -p <port>')
            sys.exit()
        elif opt in ("-a", "--address"):
            sig_ip = arg
        elif opt in ("-p", "--port"):
            sig_port = int(arg)
        elif opt in ("-d", "--isd"):
            sig_isd = int(arg)
        elif opt in ("-s", "--as"):
            sig_as = int(arg)
    print ('SIG IP is ', sig_ip)
    print ('SIG port is ', sig_port)
    print ('SIG ISD-AS is:', sig_isd, '-', sig_as)

    conf_dir = "%s/ISD%d/AS%d/endhost" % (GEN_PATH, sig_isd, sig_as)
    sig_ip_interface = haddr_parse_interface(sig_ip)
    sig_host = HostAddrIPv4(sig_ip_interface)
    sig = ScionSIG(sig_host, sig_port, conf_dir, sig_isd, sig_as)



if __name__ == '__main__':
    main(sys.argv[1:])