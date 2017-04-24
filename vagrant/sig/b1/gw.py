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
import time
import logging
from lib.thread import kill_self
import threading
from collections import deque

import pcapy

# SCION
from endhost.sciond import SCIOND_API_SOCKDIR, SCIONDaemon
from infrastructure.scion_elem import SCIONElement
from lib.defines import GEN_PATH, SCION_UDP_EH_DATA_PORT
from lib.packet.host_addr import *
from lib.packet.scion_addr import (
    ISD_AS,
    SCIONAddr)
from lib.sciond_api.parse import parse_sciond_msg
from lib.sciond_api.path_req import (
    SCIONDPathReplyError,
    SCIONDPathRequest,
)
from lib.socket import ReliableSocket
from lib.types import SCIONDMsgType as SMT
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_udp import SCIONUDPHeader
from lib.packet.packet_base import PayloadRaw
import lib.app.sciond as lib_sciond

'''
# SIG in 1-11
ETH_LEGACY_IP = 'enp0s9'
LEGACY_IP = '169.254.1.1'
LEGACY_MAC = '08:00:27:e2:f7:59'
ETH_SCION = 'enp0s8'
SCION_IP = '169.254.0.1'
SCION_PCK_LEN = 2**7 # can be between 0 and 2^16-1, I kept it small to speed up the tests
SCION_PAYLOAD_LENGTH = SCION_PCK_LEN - 8
API_TOUT = 15

LEGACY_HOST_SAME_AS = '169.254.1.2' '''


# SIG in 1-12
ETH_LEGACY_IP = 'enp0s9'
LEGACY_IP = '169.254.2.1'
LEGACY_MAC = '08:00:27:7d:70:04'
ETH_SCION = 'enp0s8'
SCION_IP = '169.254.0.2'
SCION_PCK_LEN = 2**7 # can be between 0 and 2^16-1, I kept it small to speed up the tests
SCION_PAYLOAD_LENGTH = SCION_PCK_LEN - 8
API_TOUT = 15

LEGACY_HOST_SAME_AS = '169.254.2.2'


class IP_Receiver(threading.Thread):
    '''
    Class that stores incoming IP packets into IP buffer
    '''
    def __init__(self, name, buf, run_event):
        threading.Thread.__init__(self)
        self.name = name
        self.buf = buf
        self.run_event = run_event

        '''
                    open device
                    # Arguments here are:
                    #   device
                    #   snaplen (maximum number of bytes to capture _per_packet_)
                    #   promiscious mode (1 for true)
                    #   timeout (in milliseconds)
                '''
        self.cap = pcapy.open_live(ETH_LEGACY_IP, 65536, 1, 0)


    def run(self):
        try:
            self._run()
        finally:
            logging.info("IP Receiver NOT started !!!")


    def _run(self):
        print('IP Receiver Started')

        # receive incoming IP packets and store thm in the IP buffer
        while (self.run_event.is_set()):
            # return an ip packet
            (header, packet) = self.cap.next()

            parsed = (ip_pck, dest_ip) = self._parse_packet(packet)

            # iterate only if IP pck
            if all(parsed):
                # get destination AS by SIG's list
                # THIS SELECTION MUST BE BETTER DESIGNED (PROBABLY USING THE PySubnetTree)
                if dest_ip == '169.254.1.2':
                    dest_isd = 1
                    dest_as = 11
                if dest_ip == '169.254.2.2':
                    dest_isd = 1
                    dest_as = 12

                if dest_ip == '169.254.1.1':
                    dest_isd = 1
                    dest_as = 11

                dest_ia = ISD_AS().from_values(dest_isd, dest_as)

                # add IP pck to stream
                self._add_to_stream(ip_pck)

        print('***** IP receiver exited *****')
        sys.exit(1)


    def _parse_packet(self, packet):
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
            if self._eth_addr(packet[0:6]) == LEGACY_MAC:
                '''print('Destination MAC : ', self._eth_addr(packet[0:6]), ' Source MAC : ',
                      self._eth_addr(packet[6:12]),
                      ' Protocol : ', str(eth_protocol))
                print('Version : ', str(version), ' IP Header Length : ', str(ihl), ' TTL : ', str(ttl),
                      ' Protocol : ', str(protocol), ' Source Address : ', str(s_addr), ' Destination Address : ',
                      str(d_addr))'''

                return (packet[eth_length:], str(d_addr))


        # Parse ARP packets, ARP Protocol number = 1544 (0x0806)
        elif eth_protocol == 1544:
            # discard ARP packet
            print('### ARP packet ###')
            return (None, None)

        return (None, None)


    def _eth_addr(self, a):
        # convert a string of 6 characters of ethernet address into a dash separated hex string
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
        return b


    def _add_to_stream(self, ip_pck):
        for i in ip_pck:
            self.buf.append(i)



class SCION_Sender(threading.Thread):
    '''
    Class that encapsulate IP packets into SCION ones and send the SCION packet to the right remote SIG
    '''
    def __init__(self, name, api_addr, buf, addr, dst, dport, sock, run_event, api=True):
        threading.Thread.__init__(self)
        self.name = name
        self.buf = buf
        self.dst = dst
        self.dport = dport
        self.addr = addr
        self.path_meta = None
        self.first_hop = None
        self._req_id = 0
        self.api_addr = api_addr
        self.sock = sock
        self.run_event = run_event
        self._connector = lib_sciond.init(api_addr)
        self._get_path(api) # IN THE FUTURE THE PATH SHOULD BE FETCHED ON REGULAR BASES

        self.sn = 0
        self.index = 1
        self.unused = 0
        self.offset = 0
        self.no_encap_counter = 0


    def _get_path(self, api, flush=False):
        """Request path via SCIOND API."""
        path_entries = self._try_sciond_api(flush)
        path_entry = path_entries[0]
        self.path_meta = path_entry.path()
        fh_info = path_entry.first_hop()
        fh_addr = fh_info.ipv4()
        if not fh_addr:
            fh_addr = self.dst.host
        port = fh_info.p.port or SCION_UDP_EH_DATA_PORT
        self.first_hop = (fh_addr, port)


    def _try_sciond_api(self, flush=False):
        flags = lib_sciond.PathRequestFlags(flush=flush)
        start = time.time()
        while time.time() - start < API_TOUT:
            try:
                path_entries = lib_sciond.get_paths(self.dst.isd_as, src_ia=self.addr.isd_as, flags=flags, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error during path lookup: %s" % e)
                continue
            return path_entries
        logging.critical("Unable to get path from local api.")
        kill_self()


    def run(self):
        try:
            self._run()
        finally:
            logging.info("Scion Sender NOT started !!!")


    def _run(self):
        print('SCION Sender Started')

        while (self.run_event.is_set()):
            if len(self.buf) >= (SCION_PCK_LEN - 8):
                self._send_pck(self._build_pck(), self.first_hop)

                # Increment Sequence Number if sn >= 2^32-1
                if self.sn < 4294967295:
                    self.sn = self.sn + 1
                else:
                    self.sn = 0

        print('***** SCION sender exited *****')
        sys.exit(1)


    def _send_pck(self, spkt, next_=None):
        if not next_:
            try:
                fh_info = lib_sciond.get_overlay_dest(spkt, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error getting first hop: %s" % e)
                kill_self()
            next_hop = fh_info.ipv4() or fh_info.ipv6()
            port = fh_info.p.port
        else:
            next_hop, port = next_
        assert next_hop is not None
        logging.debug("Sending (via %s:%s):\n%s", next_hop, port, spkt)
        self.sock.send(spkt.pack(), (next_hop, port))


    def _build_pck(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, self.dst)
        l4_hdr = self._create_l4_hdr()
        extensions = self._create_extensions()
        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(cmn_hdr, addr_hdr, path, extensions, l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        return spkt


    def _create_l4_hdr(self):
        return SCIONUDPHeader.from_values(self.addr, self.sock.port, self.dst, self.dport)


    def _create_extensions(self):
        return []


    def _create_payload(self, spkt):
        format = '!IHH%ss' % SCION_PAYLOAD_LENGTH
        pld = bytearray()
        for i in range(0, SCION_PAYLOAD_LENGTH):
            pld.append(self.buf.popleft())
        encap_pck = pack(format, self.sn, self.index, self.unused, pld)
        print('************************************')
        print('sn: %s\nindex: %s\nencap_pck: %s' % (self.sn, self.index, encap_pck))

        # calcolate the index field
        if self.no_encap_counter > 0:
            print('no_encap_counter:', self.no_encap_counter)
            # no encapsulated packets start in this payload
            self.index = 0
            self.no_encap_counter -= 1
        else:
            print('\nNext loop parameters:')
            self._offset_next_encap_pck(pld)
            self.index = self.offset

        return PayloadRaw(encap_pck)


    def _offset_next_encap_pck(self, payload):
        previous_offset = self.offset

        while self.offset < SCION_PAYLOAD_LENGTH:
            print('self.offset: ', self.offset)
            ip_header = payload[self.offset:self.offset + 20]
            if len(ip_header) != 20:
                print('extract missing header')
                tmp = bytearray()
                for i in range(0, (20 - len(ip_header))):
                    tmp.append(self.buf.popleft())
                ip_header = ip_header + tmp
                print('tmp: ', tmp)
                for i in tmp:
                    self.buf.append(i)

            print('ip_header: ', ip_header)
            iph = unpack('!BBHHHBBH4s4s', ip_header)
            ip_length = iph[2]
            print('ip_length: ', ip_length)
            self.offset = self.offset + ip_length
            print('self.offset: ', self.offset)


        self.no_encap_counter = int((self.offset - (SCION_PAYLOAD_LENGTH - previous_offset))/ SCION_PAYLOAD_LENGTH)
        #self.offset = (self.offset - (SCION_PAYLOAD_LENGTH - previous_offset)) % SCION_PAYLOAD_LENGTH
        self.offset = self.offset % SCION_PAYLOAD_LENGTH
        print('self.offset: ', self.offset)



class IP_Sender(threading.Thread):
    '''
    Class that decapsulate SCION packets into IP ones and send the IP packet to the right host inside the sdame AS
    '''
    def __init__(self, name, dict, discarded_spcks, run_event):
        threading.Thread.__init__(self)
        self.name = name
        self.dict = dict
        self.discorded_spcks = discarded_spcks
        self.run_event = run_event

        ICMP_CODE = socket.getprotobyname('icmp')
        self.ipsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

        self.remaining = None
        self.offset = None
        self.last_processed_spck = None


    def run(self):
        try:
            self._run()
        finally:
            logging.info("IP Sender NOT started !!!")


    def _run(self):
        print('IP Sender Started')
        counter = 0
        while (self.run_event.is_set()):
            if len(self.dict) > 0:
                if counter in self.dict:
                    self._send_procedure(counter)
                    del self.dict[counter]
                else:
                    time.sleep(1)
                    print('waited 1 second')
                # try again after 1 second or drop the packet
                if counter in self.dict:
                    self._send_procedure(counter)
                    del self.dict[counter]
                else:
                    self.discorded_spcks.append(counter)

                counter = (counter +1) % 4294967296

        print('***** IP sender exited *****')
        sys.exit(1)


    def _send_procedure(self, sn):
        spck = self.dict[sn]
        index = spck.index
        self._send_ip_pcks(spck)
        print('index pck to send is: ', index)


    def _send_ip_pcks(self, spck):
        sn = spck.sn
        index = spck.index
        self.offset = index
        payload = spck.payload
        ip_len = 0

        # send remaining payload of sn-1
        if ((self.remaining is not None) & (self.last_processed_spck == sn-1)):
            payload = self.remaining + payload
            ip_len = len(self.remaining) + index
            ip_pld = payload[0:ip_len]
            self.ipsock.sendto(ip_pld, (LEGACY_HOST_SAME_AS, 1))

        #send payload of sn
        if index != 0:
            while self.offset < SCION_PAYLOAD_LENGTH:
                ip_header = spck.payload[self.offset + ip_len:self.offset + ip_len + 20]
                if len(ip_header) != 20:
                    self.remaining = ip_header
                    self.last_processed_spck = sn
                    break

                print('ip_header: ', ip_header)
                iph = unpack('!BBHHHBBH4s4s', ip_header)
                ip_len = iph[2]
                ip_pld = payload[self.offset:self.offset + ip_len]
                if self.offset+ip_len < SCION_PAYLOAD_LENGTH:
                    self.ipsock.sendto(ip_pld, (LEGACY_HOST_SAME_AS, 1))
                    self.offset = self.offset + ip_len
                else:
                    self.remaining = ip_header + ip_pld
                    self.last_processed_spck = sn
                    break

        else:
            self.remaining = self.remaining + payload



    def _parse_scion_pck(self, sn, index, unused, payload):
        decap_pck = Decapsulated_Packet(sn, index, unused)
        eth_length = 14
        remaining = payload
        counter = 0

        # prepend cut ip packet to the payload on the newest SCION packet
        if self.dict[sn-1] is not None & self.dict[sn-1].get_cut_ip() is not None:
            remaining = self.cut_ip + remaining
        while len(remaining) is not 0:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = remaining[eth_length:20 + eth_length]

            # now unpack them :)
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            total_lenght = int(iph[2], 2)
            if total_lenght < len(remaining):
                ip_pcks[counter] = remaining[:total_lenght]
                remaining = remaining[total_lenght:]
                counter = counter + 1
            else:
                # ip packet is cut
                self.cut_ip = remaining



class Decapsulated_Packet(object):

    def __init__(self, sn, index, unused, payload, parsed=False):
        """
        Create a decapsulated packed that keep track of the IP packets that were encapsulated into a specific SCION packet.
        If an IP packet has been split into different SCION packets, this class helps to reassemble the original packet
        """
        self.sn = sn
        self.index = index
        self.unused = unused
        self.payload = payload
        self.parsed = parsed
        self.ip_pcks = {}
        self.cut_ip = None


    def add_ip(self, order, pck):
        self.ip_pcks[order] = pck


    def update_cut_ip(self, data):
        self.cut_ip = data


    def get_cut_ip(self):
        if self.parsed is not False:
            return self.cut_ip
        else:
            return None




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

        super().__init__('sig', self.conf_dir, host_addr=sig_host, port=0)

        print ('Starting GW...')
        print ('The legacy IP interface is ', ETH_LEGACY_IP, ' and the SCION interface is ', ETH_SCION)


        # sig address
        sig_ia = ISD_AS().from_values(self.sig_isd, self.sig_as)
        sig_addr = SCIONAddr().from_values(sig_ia, self.sig_host)

        # create SIG instance and register to the SCION Daemon
        api_addr = SCIOND_API_SOCKDIR + "sd%s.sock" % sig_addr.isd_as


        # create IP byte stream
        # IN THE FUTURE THERE MUST BE A STREAM FOR EACH REMOTE AS
        ip_buf = deque()

        # create dictionary of SCION packets received
        self.spcks_dict = {}

        # list of all the discarded scion packets received out of order
        self.discarded_spcks = []

        # set up ReliableSocket to Dispatcher
        ### ADD SVC VALUE FOR THE SIG SERVICE; ADD THE SIG (IP & PORT) IN THE TOPOLOGY FILE !!!
        print('sig addr:', sig_addr)
        print('sig port: ', self.sig_port)
        scion_sock = self._create_socket(sig_addr, self.sig_port)
        # self._socks.add(scion_sock, self._encap_accept)


        # killing event for all the threads
        run_event = threading.Event()
        run_event.set()


        # create an Ip_Receiver that processes all the incoming IP packets
        ip_receiver = IP_Receiver("IP_Receiver-Thread", ip_buf, run_event)
        ip_receiver.start()

        '''
        # only destination for now is SIG at 1-12
        dest_ia = ISD_AS().from_values(1, 12)
        dest_host = HostAddrIPv4('169.254.0.2')
        dest_port = 40500
        dest_sig_addr = SCIONAddr().from_values(dest_ia, dest_host)'''


        # only destination for now is SIG at 1-11
        dest_ia = ISD_AS().from_values(1, 11)
        dest_host = HostAddrIPv4('169.254.0.1')
        dest_port = 30100
        dest_sig_addr = SCIONAddr().from_values(dest_ia, dest_host)


        # create a SCION_Sender that processes all the IP's buffers, decides which one to has the priority
        # and forwards the SCION packets to respective the remote SIG
        scion_sender = SCION_Sender("SCION_Sender-Thread", api_addr, ip_buf, sig_addr, dest_sig_addr, dest_port, scion_sock, run_event, api=True)
        scion_sender.start()

        # create IP_Sender
        ip_sender = IP_Sender("IP_Sender-Thread", self.spcks_dict, self.discarded_spcks, run_event)
        ip_sender.start()

        # loop for SCION Receiver
        self._SCION_Receiver(run_event, scion_sock)


    def _SCION_Receiver(self, event, sock):
        try:
            while 1:
                self._encap_recv(sock)

        # kill all threads if needed
        except KeyboardInterrupt:
            print('Attempting to close threads')
            event.clear()
            time.sleep(1)
            sock.close()
            print('All threads successfully closed')



    def _run_sciond(self, conf_dir, sig_addr):
        # start SCION Daemon
        api_addr = SCIOND_API_SOCKDIR + "sd%s.sock" % (self.NAME, sig_addr.isd_as)
        return self._start_sciond(conf_dir, sig_addr, api=True, api_addr=api_addr), api_addr



    def _start_sciond(self, conf_dir, addr, api=False, port=0, api_addr=None):
        # start the SCION daemon
        return SCIONDaemon.start(conf_dir, addr.host, api_addr=api_addr, run_local_api=api, port=port)


    def _create_socket(self, sig_addr, sig_port):
        # set up ReliableSocket to Dispatcher
        ### ADD SVC VALUE FOR THE SIG SERVICE; ADD THE SIG (IP & PORT) IN THE TOPOLOGY FILE !!!
        sock = ReliableSocket(reg=(sig_addr, sig_port, True, None))
        #sock.settimeout(1.0)
        return sock


    def _encap_accept(self, sock):
        s = sock.accept()
        if not s:
            logging.error("accept failed")
            return
        self._socks.add(s, self._encap_recv)


    def _encap_recv(self, sock):
        packet = sock.recv()[0]
        spck = SCIONL4Packet(packet)
        pld = spck.get_payload()
        if pld is None:
            return
        self._packet_put(pld)


    def _packet_put(self, packet):
        spck = packet.pack()
        print('SCION pld received: ', spck)
        sn, index, unused, payload = self._unpack_scion_pck(spck)
        if sn in self.discarded_spcks:
            print('scion packet received out of order and in late')
        else:
            self.spcks_dict[sn] = Decapsulated_Packet(sn, index, unused, payload)
            print('added SCION pck with sn: %s and index: %s' % (sn, index))


    def _unpack_scion_pck(self, spck):
        print('spck lenght: ', len(spck))
        format = '!IHH%ss' % (len(spck)-8)
        sn, index, unused, payload = struct.unpack(format, spck)
        return sn, index, unused, payload



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

    conf_dir = "%s/ISD%d/AS%d/endhost" % (GEN_PATH, sig_isd, sig_as)
    sig_ip_interface = haddr_parse_interface(sig_ip)
    sig_host = HostAddrIPv4(sig_ip_interface)
    sig = ScionSIG(sig_host, sig_port, conf_dir, sig_isd, sig_as)


if __name__ == '__main__':
    main(sys.argv[1:])


