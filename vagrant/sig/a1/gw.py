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


# GW has two interfaces and is running on localhost
ETH_LEGACY_IP = 'enp0s9'
LEGACY_IP = '169.254.1.1'
LEGACY_MAC = '08:00:27:e2:f7:59'
ETH_SCION = 'enp0s8'
SCION_IP = '169.254.0.1'
SCION_PCK_LEN = 2**7 # can be between 0 and 2^16-1, I kept it small to speed up the tests
API_TOUT = 15



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
        sn = 0
        index = 0
        unused = 0


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
                self._add_to_stream(dest_ia, sn, index, unused, ip_pck)
                curr_pos = len(self.buf)

                # update index
                if curr_pos >= SCION_PCK_LEN:
                    index = curr_pos % SCION_PCK_LEN

                # Increment Sequence Number if sn >= 2^32-1
                if sn < 4294967295:
                    sn = sn + 1
                else:
                    sn = 0

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
                print('Destination MAC : ', self._eth_addr(packet[0:6]), ' Source MAC : ',
                      self._eth_addr(packet[6:12]),
                      ' Protocol : ', str(eth_protocol))
                print('Version : ', str(version), ' IP Header Length : ', str(ihl), ' TTL : ', str(ttl),
                      ' Protocol : ', str(protocol), ' Source Address : ', str(s_addr), ' Destination Address : ',
                      str(d_addr))

                return (packet[eth_length:], str(d_addr))


        # Parse ARP packets, ARP Protocol number = 1544 (0x0806)
        elif eth_protocol == 1544:
            # do nothing for now.....
            print('### ARP packet ###')
            return (None, None)

        return (None, None)


    def _eth_addr(self, a):
        # convert a string of 6 characters of ethernet address into a dash separated hex string
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
        return b


    def _add_to_stream(self, dest_ia, sn, index, unused, ip_pck):
        # FOR NOW dest_ia IS ONLY 1-12, LATER THERE WILL BE A BYTE STREAM FOR EACH REMOTE ISD-AS
        format = '!IHH%ss' % (len(ip_pck))
        new_ip_pck = pack(format, sn, index, unused, ip_pck)
        for i in new_ip_pck:
            self.buf.append(i)


class SCION_Sender(threading.Thread):
    '''
    Class that encapsulate IP packets into SCION ones and send the SCION packet to the right remote SIG
    '''
    def __init__(self, name, sd, api_addr, buf, addr, dst, dport, sock, run_event, api=True):
        threading.Thread.__init__(self)
        self.name = name
        self.buf = buf
        self.dst = dst
        self.dport = dport
        self.addr = addr
        self.path_meta = None
        self.first_hop = None
        self._req_id = 0
        self.sd = sd
        self.api_addr = api_addr
        self.sock = sock
        self.run_event = run_event
        self._get_path(api) # IN THE FUTURE THE PATH SHOULD BE FETCHED ON REGULAR BASES


    def _get_path(self, api):
        if api:
            self._get_path_via_api()
        else:
            self._get_path_direct()


    def _get_path_via_api(self):
        """Request path via SCIOND API."""
        response = self._try_sciond_api()
        path_entry = response.path_entry(0)
        self.path_meta = path_entry.path()
        fh_addr = path_entry.ipv4()
        if not fh_addr:
            print('no fh_addr !!!')
            # fh_addr = self.dst.host
        port = path_entry.p.port or SCION_UDP_EH_DATA_PORT
        self.first_hop = (fh_addr, port)


    def _try_sciond_api(self):
        sock = ReliableSocket()
        request = SCIONDPathRequest.from_values(self._req_id, self.dst.isd_as)
        packed = request.pack_full()
        self._req_id += 1
        start = time.time()
        try:
            sock.connect(self.api_addr)
        except OSError as e:
            print('Error connecting to sciond: %s' % e)
            kill_self()
        while time.time() - start < API_TOUT:
            print('Sending path request to local API at %s: %s' % (self.api_addr, request))
            sock.send(packed)
            data = sock.recv()[0]
            if data:
                response = parse_sciond_msg(data)
                if response.MSG_TYPE != SMT.PATH_REPLY:
                    print('Unexpected SCIOND msg type received: %s' % response.NAME)
                    continue
                if response.p.errorCode != SCIONDPathReplyError.OK:
                    print('SCIOND returned an error (code=%d): %s' % (response.p.errorCode, SCIONDPathReplyError.describe(response.p.errorCode)))
                    continue
                sock.close()
                return response
            print('Empty response from local api.')
        print('Unable to get path from local api.')
        sock.close()
        kill_self()


    def _get_path_direct(self, flags=0):
        """Request path from SCIOND object."""
        paths = []
        for _ in range(5):
            paths, _ = self.sd.get_paths(self.dst.isd_as)
            if paths:
                break
        else:
            logging.critical("Unable to get path directly from sciond")
            kill_self()
        self.path_meta = paths[0]
        self.first_hop = None


    def run(self):
        try:
            self._run()
        finally:
            logging.info("Scion Sender NOT started !!!")


    def _run(self):
        print('SCION Sender Started')
        while (self.run_event.is_set()):
            if len(self.buf) >= SCION_PCK_LEN:
                self._send_pck(self._build_pck(), self.first_hop)
        print('***** SCION sender exited *****')
        sys.exit(1)

    def _send_pck(self, spkt, next_=None):
        next_hop, port = next_ or self.sd.get_first_hop(spkt)
        if next_hop is not None:
            print('Sending (via %s:%s):\n%s' % (next_hop, port, spkt))
            self.sock.send(spkt.pack(), (next_hop, port))
        if self.path_meta:
            print('Interfaces: %s' % ', '.join([str(ifentry) for ifentry in self.path_meta.iter_ifs()]))


    def _build_pck(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, self.dst)
        l4_hdr = self._create_l4_hdr()
        extensions = self._create_extensions()
        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, extensions, l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        return spkt


    def _create_l4_hdr(self):
        return SCIONUDPHeader.from_values(self.addr, self.sock.port, self.dst, self.dport)


    def _create_extensions(self):
        return []


    def _create_payload(self, spkt):
        #return PayloadRaw(self.buf.read(SCION_PCK_LEN))
        pck = bytearray()
        for i in range(1, SCION_PCK_LEN + 1):
            pck.append(self.buf.popleft())
        return PayloadRaw(pck)


class SCION_Receiver(threading.Thread, SCIONElement):
    '''
    Class that encapsulate IP packets into SCION ones and send the SCION packet to the right remote SIG
    '''
    def __init__(self, name, buf, sock, run_event):
        threading.Thread.__init__(self)
        self.name = name
        self.buf = buf
        self.sock = sock
        self.run_event = run_event
        self._socks.add(self.sock, self.handle_accept)  # SUBSTITUTE THE CALLBACK WITH SELF.ENCAP_ACCEPT !!!


    def run(self):
        try:
            self._run()
        finally:
            logging.info("Scion Receiver NOT started !!!")


    def _run(self):
        print('SCION Receiver Started')
        while (self.run_event.is_set()):
            spck = self._recv()
            print('SCION BUFFER BEFORE: ', len(self.buf))
            if spck is not None:
                for i in spck:
                    self.buf.append(i)
            print('SCION BUFFER AFTER: ', len(self.buf))
        print('***** SCION receiver exited *****')
        sys.exit(1)


    def _recv(self):
        try:
            packet = self.sock.recv()[0]
            print('INSIDE TRY BLOCK')
        except socket.timeout:
            return None
        return SCIONL4Packet(packet)



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

        super().__init__('sig', self.conf_dir, host_addr=sig_host, port=self.sig_port)

        print ('Starting GW...')
        print ('The legacy IP interface is ', ETH_LEGACY_IP, ' and the SCION interface is ', ETH_SCION)


        # sig address
        sig_ia = ISD_AS().from_values(self.sig_isd, self.sig_as)
        sig_addr = SCIONAddr().from_values(sig_ia, self.sig_host)

        # create SIG instance and register to the SCION Daemon
        sd, api_addr = self._run_sciond(self.conf_dir, sig_addr)


        # set up ReliableSocket to Dispatcher
        ### ADD SVC VALUE FOR THE SIG SERVICE; ADD THE SIG (IP & PORT) IN THE TOPOLOGY FILE !!!
        scion_sock = self._create_socket(sig_addr, self.sig_port)


        # create IP byte stream
        # IN THE FUTURE THERE MUST BE A STREAM FOR EACH REMOTE AS
        ipbuf = deque()


        # create SCION stream
        sbuf = deque()


        # killing event for all the threads
        run_event = threading.Event()
        run_event.set()


        # create an Ip_Receiver that processes all the incoming IP packets
        ip_receiver = IP_Receiver("IP_Receiver-Thread", ipbuf, run_event)
        ip_receiver.start()


        # only destination for now is SIG at 1-12
        dest_ia = ISD_AS().from_values(1, 12)
        dest_host = HostAddrIPv4('169.254.2.2')
        dest_port = 30150
        dest_sig_addr = SCIONAddr().from_values(dest_ia, dest_host)


        # create a SCION_Sender that processes all the IP's buffers, decides which one to has the priority
        # and forwards the SCION packets to respective the remote SIG
        scion_sender = SCION_Sender("SCION_Sender-Thread", sd, api_addr, ipbuf, sig_addr, dest_sig_addr, dest_port, scion_sock, run_event, api=True)
        scion_sender.start()


        # create a SCION_Receiver that processes all the incoming SCION packets
        #scion_receiver = SCION_Receiver('SCION_Receiver-Thread', sbuf, scion_sock, run_event)
        #scion_receiver.start()


        # kill all threads if needed
        try:
            while 1:
                time.sleep(.1)
        except KeyboardInterrupt:
            print ('Attempting to close threads')
            run_event.clear()
            time.sleep(1)
            # stop SCIOND
            sd.stop()
            scion_sock.close()
            print ('All threads successfully closed')



    def _run_sciond(self, conf_dir, sig_addr):
        # start SCION Daemon
        api_addr = SCIOND_API_SOCKDIR + "%s_%s.sock" % (self.NAME, sig_addr.isd_as)
        return self._start_sciond(conf_dir, sig_addr, api=True, api_addr=api_addr), api_addr



    def _start_sciond(self, conf_dir, addr, api=False, port=0, api_addr=None):
        # start the SCION daemon
        return SCIONDaemon.start(conf_dir, addr.host, api_addr=api_addr, run_local_api=api, port=port)


    def _create_socket(self, sig_addr, sig_port):
        # set up ReliableSocket to Dispatcher
        ### ADD SVC VALUE FOR THE SIG SERVICE; ADD THE SIG (IP & PORT) IN THE TOPOLOGY FILE !!!
        sock = ReliableSocket(reg=(sig_addr, sig_port, None, None))
        return sock



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


