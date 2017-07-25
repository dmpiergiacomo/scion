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
import datetime

import pcapy
import scapy.all as scapy

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


# SIG in 1-11
ETH_LEGACY_IP = 'enp0s9'
LEGACY_IP = '169.254.1.1'
LEGACY_MAC = '08:00:27:e2:f7:59'
ETH_SCION = 'enp0s8'
SCION_IP = '169.254.0.1'
SCION_PCK_LEN = 2**7 # can be between 0 and 2^16-1, I kept it small to speed up the tests
SCION_PAYLOAD_LENGTH = SCION_PCK_LEN - 8
API_TOUT = 15

LEGACY_HOST_SAME_AS = '169.254.1.2'

'''
# SIG in 1-12
ETH_LEGACY_IP = 'enp0s9'
LEGACY_IP = '169.254.2.1'
LEGACY_MAC = '08:00:27:7d:70:04'
ETH_SCION = 'enp0s8'
SCION_IP = '169.254.0.2'
SCION_PCK_LEN = 2**7 # can be between 0 and 2^16-1, I kept it small to speed up the tests
SCION_PAYLOAD_LENGTH = SCION_PCK_LEN - 8
API_TOUT = 15
LEGACY_HOST_SAME_AS = '169.254.2.2' '''


HALF_RTT = 1000 # 1/2 RTT is for now fixed to 1 second

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

                if dest_ip == '169.254.4.2':
                    print('Destination is 169.254.4.2')
                    # send trough direct Internet link
                    ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                    scapy.sendp(ethernet / scapy.Raw(ip_pck), iface='enp0s10')
                    continue

                '''if dest_ip == '169.254.1.2':
                    print('Destination is 169.254.1.2')
                    # send trough direct Internet link
                    ethernet = scapy.Ether(src='08:00:27:08:9c:bd', dst='08:00:27:59:3d:4a', type=0x0800)
                    scapy.sendp(ethernet / scapy.Raw(ip_pck), iface='enp0s8')
                    continue'''


                dest_ia = ISD_AS().from_values(dest_isd, dest_as)

                # add IP pck to stream
                self._add_to_stream(ip_pck)


        print('***** IP receiver exited *****')
        sys.exit(1)


    def _parse_packet(self, packet):
        print('packet length: ', len(packet))
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

            if len(ip_header) == 20:

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
        # print('buffer after add: ', self.buf)



class Second_IP_Receiver(threading.Thread):
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

        self.cap = pcapy.open_live('enp0s10', 65536, 1, 0)

    def run(self):
        try:
            self._run()
        finally:
            logging.info("IP Receiver NOT started !!!")


    def _run(self):
        print('Second IP Receiver Started')

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

                '''if dest_ip == '169.254.4.2':
                    print('Destination is 169.254.4.2')
                    # send trough direct Internet link
                    ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                    scapy.sendp(ethernet / scapy.Raw(ip_pck), iface='enp0s10')
                    continue'''

                if dest_ip == '169.254.1.2':
                    print('Destination is 169.254.1.2')
                    # send trough direct Internet link
                    ethernet = scapy.Ether(src='08:00:27:e2:f7:59', dst='08:00:27:94:f9:9c', type=0x0800)
                    scapy.sendp(ethernet / scapy.Raw(ip_pck), iface='enp0s9')
                    continue


                dest_ia = ISD_AS().from_values(dest_isd, dest_as)

                # add IP pck to stream
                self._add_to_stream(ip_pck)


        print('***** IP receiver exited *****')
        sys.exit(1)


    def _parse_packet(self, packet):
        print('packet length: ', len(packet))
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

            if len(ip_header) == 20:

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
                if self._eth_addr(packet[0:6]) == '08:00:27:59:3d:4a':
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
        # print('buffer after add: ', self.buf)



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

        # UNCOMMENT IN CASE YOU WANT TO DROP SOM SCION PACKETS
        counter = 0
        sn_3 = None
        while (self.run_event.is_set()):
            if len(self.buf) >= (SCION_PCK_LEN - 8):

                ''' TEST TO DROP SOME RANDOM PACKETS
                print('counter: ', counter)
                to_send = self._build_pck()
                if counter != 4:
                    self._send_pck(to_send, self.first_hop)'''

                ''' TEST TO DELAY SN=4 RESPECT SN=5; IF DELAY>1/RTT ATTACK EXPLAINED IN POINT 9) OF DOC. FILE HAPPENS
                if counter == 3:
                    sn_3 = self._build_pck()
                elif counter == 4:
                    self._send_pck(self._build_pck(), self.first_hop)
                    self._send_pck(sn_3, self.first_hop)
                else:
                    self._send_pck(self._build_pck(), self.first_hop)'''

                self._send_pck(self._build_pck(), self.first_hop)

                # Increment Sequence Number if sn >= 2^32-1
                if self.sn < 4294967295:
                    self.sn = self.sn + 1
                else:
                    self.sn = 0

                # UNCOMMENT IN CASE YOU WANT TO DROP SOM SCION PACKETS
                counter = (counter + 1) % 5

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
        # print('buffer after rem: ', self.buf)
        self.index = self.offset + 1
        encap_pck = pack(format, self.sn, self.index, self.unused, pld)
        # print('************************************')
        #print('sn: %s\nindex: %s\nencap_pck: %s' % (self.sn, self.index, encap_pck))

        # calcolate the index field
        if self.no_encap_counter > 0:
            print('no_encap_counter:', self.no_encap_counter)
            # no encapsulated packets start in this payload
            self.offset = -1
            self.no_encap_counter -= 1
        else:
            print('\nNext loop parameters:')
            self._offset_next_encap_pck(pld)
            self.index = self.offset

        return PayloadRaw(encap_pck)


    def _offset_next_encap_pck(self, payload):
        previous_offset = self.offset

        while self.offset < SCION_PAYLOAD_LENGTH:
            # print('self.offset: ', self.offset)
            ip_header = payload[self.offset:self.offset + 20]
            if len(ip_header) != 20:
                # print('extract missing header')
                tmp = bytearray()
                for i in range(0, (20 - len(ip_header))):
                    tmp.append(self.buf.popleft())
                ip_header = ip_header + tmp
                # print('tmp: ', tmp)
                for i in range (len(tmp)):
                    self.buf.appendleft(tmp[len(tmp)-1-i])

            # print('ip_header: ', ip_header)
            iph = unpack('!BBHHHBBH4s4s', ip_header)
            ip_length = iph[2]
            # print('ip_length: ', ip_length)
            self.offset = self.offset + ip_length
            # print('self.offset: ', self.offset)


        self.no_encap_counter = int((self.offset - (SCION_PAYLOAD_LENGTH - previous_offset))/ SCION_PAYLOAD_LENGTH)
        #self.offset = (self.offset - (SCION_PAYLOAD_LENGTH - previous_offset)) % SCION_PAYLOAD_LENGTH
        self.offset = self.offset % SCION_PAYLOAD_LENGTH
        # print('self.offset: ', self.offset)



class IP_Sender(threading.Thread):
    '''
    Class that decapsulate SCION packets into IP ones and send the IP packet to the right host inside the sdame AS
    '''
    def __init__(self, name, dict, splitIP_tail, splitIP_head, ipsock, run_event):
        threading.Thread.__init__(self)
        self.name = name
        self.dict = dict
        self.ipsock = ipsock
        self.run_event = run_event


        self.remaining = None
        self.offset = None
        self.last_processed_spck = None

        # splitIP_tail[sn] contains the last fragment of the last IP pck contained in SCION pck with SN-1
        self.splitIP_tail = splitIP_tail
        # splitIP_head[sn] contains the first fragment of the last IP pck contained in SCION pck SN
        # or an intermediary fragment if index=0
        self.splitIP_head = splitIP_head


    def run(self):
        try:
            self._run()
        finally:
            logging.info("IP Sender NOT started !!!")


    def _run(self):
        print('IP Sender Started')
        sn_to_send = 0
        while (self.run_event.is_set()):
            if len(self.dict) > 0:
                if self.dict.get(sn_to_send) is not None:
                    self._send_procedure(sn_to_send)

                sn_to_send = (sn_to_send +1) % 4294967296

        print('***** IP sender exited *****')
        sys.exit(1)


    def _send_procedure(self, sn):
        spck = self.dict[sn]
        index = spck.index
        payload = spck.payload
        # print('*******************************************************')
        # cprint('index is: ', index)

        # no IP packets starts in this payload
        if index == 0:
            # print('index=0 so splitIP_head')
            self.splitIP_head[sn] = (False, payload)  # tuple: (IP_pck_starts_in_this_elem, part_of_payload_of_fragmented_pck)

            # packet processed, time to remove it from dictionary
            del self.dict[sn]
        else:
            # print('try to send pck')
            self._send_previous_fragmented_ip_pck(spck)
            self._send_ip_pcks_in_this_encap_pck(spck)


    def _send_previous_fragmented_ip_pck(self, spck):
        sn = spck.sn
        index = spck.index
        # print('_send_previous_fragmented_ip_pck')

        if self.splitIP_head.get((sn-1)%4294967296) is not None:
            if index == 1:
                # if the previous IP pck had index=0 it has not been sent yet and it has to be sent
                pld = b''
            else:
                # when index>1 part of the previous IP pck is in the current encap pck
                pld = spck.payload[:index]

            iterator = (sn-1)%4294967296
            retrieved_fragments = []
            while(True):
                if self.splitIP_head.get(iterator) is None:
                    # part of pck has been lost
                    pld = None
                    break
                elif self.splitIP_head[iterator][0] == True:
                    # starting point of the IP pck found
                    pld = self.splitIP_head[iterator][1] + pld
                    retrieved_fragments.append(iterator)
                    break
                elif self.splitIP_head[iterator][0] == False:
                    # starting point of the IP pck not found
                    pld = self.splitIP_head[iterator][1] + pld
                    retrieved_fragments.append(iterator)

                iterator = (iterator - 1) % 4294967296

            if pld is not None:
                #print('pld is: ', pld)
                # ethernet = scapy.Ether(src='08:00:27:e2:f7:59', dst='08:00:27:94:f9:9c', type=0x0800) (send to a2)
                ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                # scapy.sendp(ethernet / scapy.Raw(pld), iface=ETH_LEGACY_IP) (send to a2)
                scapy.sendp(ethernet / scapy.Raw(pld), iface='enp0s10')
                # print('sent pld: ', pld)
                for i in retrieved_fragments:
                    # remove from dictionary fragments sent correctly
                    del self.splitIP_head[i]

        else:
            # it means that the packet with sequence number = SN-1 was already sent or lost/in late
            self.splitIP_tail[sn] = spck.payload[:index]


    def _send_ip_pcks_in_this_encap_pck(self, spck):
        sn = spck.sn
        index = spck.index
        pld = spck.payload
        # print('_send_ip_pcks_in_this_encap_pck')

        # print('pld is:', pld)

        self.offset = index -1

        while self.offset <= SCION_PAYLOAD_LENGTH:
            ip_header = pld[self.offset:self.offset + 20]
            # print('ip_header: ', ip_header)
            if len(ip_header) != 20:
                # print('header too short')
                self.splitIP_head[sn] = (True, ip_header)
                # packet processed, time to remove it from dictionary
                if sn in self.dict:
                    del self.dict[sn]
                break

            else:
                iph = unpack('!BBHHHBBH4s4s', ip_header)
                ip_len = iph[2]
                # print('ip_length :', ip_len)
                ip_pck = pld[self.offset:self.offset + ip_len]
                #print('pld is: ', ip_pck)
                if self.offset + ip_len <= SCION_PAYLOAD_LENGTH:
                    # ethernet = scapy.Ether(src='08:00:27:e2:f7:59', dst='08:00:27:94:f9:9c', type=0x0800) (send to a2)
                    ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                    # scapy.sendp(ethernet/scapy.Raw(pld), iface=ETH_LEGACY_IP) (send to a2)
                    scapy.sendp(ethernet/scapy.Raw(ip_pck), iface='enp0s10')
                    # print('sent pld: ', ip_pck)
                    self.offset = self.offset + ip_len
                    # print('self.offset: ', self.offset)
                else:
                    self.splitIP_head[sn] = (True, ip_pck)
                    # packet processed, time to remove it from dictionary
                    if sn in self.dict:
                        del self.dict[sn]
                    break


    def _send_ip_pcks_old(self, spck):
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
            #self.ipsock.sendto(ip_pld, (LEGACY_HOST_SAME_AS, 1))
            ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
            scapy.sendp(ethernet / scapy.Raw(ip_pld), iface='enp0s10')
            print('sent within _send_ip_pcks_old')

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
                    #self.ipsock.sendto(ip_pld, (LEGACY_HOST_SAME_AS, 1))
                    ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                    scapy.sendp(ethernet / scapy.Raw(ip_pld), iface='enp0s10')
                    print('sent within _send_ip_pcks_old')
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


class Send_Delayed_Packets(threading.Thread):
    '''
    Class that decapsulate SCION packets into IP ones and send the IP packet to the right host inside the sdame AS
    '''
    def __init__(self, name, spcks_dict, lost_or_delayed, delayed_spcks, splitIP_tail, splitIP_head, ipsock, run_event):
        threading.Thread.__init__(self)
        self.name = name
        self.dict = spcks_dict
        self.lost_or_delayed = lost_or_delayed
        self.delayed_spcks = delayed_spcks
        self.splitIP_tail = splitIP_tail
        self.splitIP_head = splitIP_head
        self.ipsock = ipsock
        self.run_event = run_event

    def run(self):
        try:
            self._run()
        finally:
            logging.info("Send_Delayed_Packets NOT started !!!")


    def _run(self):
        print('Send_Delayed_Packets Started')

        while (self.run_event.is_set()):
            current_time = datetime.datetime.now()

            if self.lost_or_delayed:
                sn, arrival_time = self.lost_or_delayed.pop() # return and remove delayed pck with shortest time to live
                if (current_time - arrival_time).total_seconds() > HALF_RTT:
                    # packet is too much in late, discard preceding fragments and it (N.B. pop() already done)
                    self._discard_preceding_fragments(sn)
                    self._discard_following_fragments(sn)

                    if sn in self.dict:
                        #notice that if the pck was lost, self.dict[sn] is empty
                        del self.dict[sn]
                    if sn in self.delayed_spcks:
                        # notice that if the pck was lost, self.delayed_spcks[sn] is (False, None)
                        del self.delayed_spcks[sn]

                else:
                    # try to send this pck and related fragments

                    success_with_preceding = False
                    success_with_following = False
                    if sn in self.dict:
                        #notice that if the pck was lost, self.dict[sn] is empty
                        success_with_preceding = self._send_preceding_fragments(sn)
                        success_with_following = self._send_following_fragments(sn)

                    if success_with_preceding and success_with_following == False:
                        # not all fragments sent, but still time to try so reinsert tuple in previous position
                        self.lost_or_delayed.append((sn, arrival_time))
                    else:
                        # all fragments sent properly

                        if sn in self.dict:
                            # notice that if the pck was lost, self.dict[sn] is empty
                            del self.dict[sn]
                        if sn in self.delayed_spcks:
                            # notice that if the pck was lost, self.delayed_spcks[sn] is (False, None)
                            del self.delayed_spcks[sn]

        print('***** Send_Delayed_Packets sender exited *****')
        sys.exit(1)


    def _discard_preceding_fragments(self, sn):

        if self.splitIP_head.get((sn - 1) % 4294967296) is not None:

            iterator = (sn - 1) % 4294967296
            retrieved_fragments = []
            while(True):
                if self.splitIP_head.get(iterator) is None:
                    break
                elif self.splitIP_head[iterator][0] == True:
                    # starting point of the IP pck found
                    retrieved_fragments.append(iterator)
                    break
                elif self.splitIP_head[iterator][0] == False:
                    # starting point of the IP pck not found
                    retrieved_fragments.append(iterator)

                iterator = (iterator - 1) % 4294967296

            if retrieved_fragments:
                for i in retrieved_fragments:
                    del self.splitIP_head[i]


    def _discard_following_fragments(self, sn):

        if self.splitIP_tail.get((sn + 1) % 4294967296) is not None:
            # in this case the next fragment is the tail

            # there can be only one following IP fragment
            del self.splitIP_tail[(sn + 1) % 4294967296]

        elif self.splitIP_head.get((sn + 1) % 4294967296) is not None:
            # in this case the next fragment is a middle fragment of a pck that had index=0

            iterator = (sn + 1) % 4294967296
            retrieved_fragments = []
            while (True):
                if (self.splitIP_head.get(iterator) is None) or (self.splitIP_head[iterator][0] == True):
                    # either the next pck is lost or it contains the tail of the fragmented IP

                    if (self.splitIP_tail.get(iterator) is not None) and (self.splitIP_head[iterator][0] == True):
                        del self.splitIP_tail[iterator]
                    break
                elif self.splitIP_head[iterator][0] == False:
                    # starting point of the IP pck not found
                    retrieved_fragments.append(iterator)

                iterator = (iterator + 1) % 4294967296

            if retrieved_fragments:
                for i in retrieved_fragments:
                    del self.splitIP_head[i]


    def _send_preceding_fragments(self, sn):
        spck = self.dict[sn]
        index = spck.index

        if self.splitIP_head.get((sn - 1) % 4294967296) is not None:
            if index == 1:
                # if the previous IP pck had index=0 it has not been sent yet and it has to be sent
                pld = None
            else:
                # when index>1 part of the previous IP pck is in the current encap pck
                pld = spck.payload[:index]

            iterator = (sn - 1) % 4294967296
            retrieved_fragments = []
            while (True):
                if self.splitIP_head.get(iterator) is None:
                    # part of pck has been lost
                    pld = None
                    break
                elif self.splitIP_head[iterator][0] == True:
                    # starting point of the IP pck found
                    pld = self.splitIP_head[iterator][1] + pld
                    retrieved_fragments.append(iterator)
                    break
                elif self.splitIP_head[iterator][0] == False:
                    # starting point of the IP pck not found
                    pld = self.splitIP_head[iterator][1] + pld
                    retrieved_fragments.append(iterator)

                iterator = (iterator - 1) % 4294967296

            if pld is not None:
                #self.ipsock.sendto(pld, (LEGACY_HOST_SAME_AS, 1))
                #self.ipsock.sendto(pld, ('169.254.4.2', 1))
                ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                scapy.sendp(ethernet / scapy.Raw(pld), iface='enp0s10')
                print('sent within _send_preceding_fragments')
                for i in retrieved_fragments:
                    # remove from dictionary packets sent correctly
                    del self.dict[i]

        else:
            # it means that the packet with sequence number = SN-1 was lost
            self.splitIP_tail[sn] = spck.payload[:index]


    def _send_following_fragments(self, sn):
        spck = self.dict[sn]
        index = spck.index
        pld = spck.payload
        self.offset = index
        ip_len = 0

        while self.offset <= SCION_PAYLOAD_LENGTH:
            ip_header = pld[self.offset + ip_len:self.offset + ip_len + 20] # MAYBE I SHOULD REMOVE '+ ip_len'
            if len(ip_header) != 20:
                self.splitIP_head[sn] = (True, ip_header)
                # packet processed, time to remove it from dictionary
                del self.dict[sn]
                break

            else:
                iph = unpack('!BBHHHBBH4s4s', ip_header)
                ip_len = iph[2]
                ip_pck = pld[self.offset:self.offset + ip_len]
                if self.offset + ip_len <= SCION_PAYLOAD_LENGTH:
                    #self.ipsock.sendto(ip_pck, (LEGACY_HOST_SAME_AS, 1))
                    #self.ipsock.sendto(ip_pck, ('169.254.4.2', 1))
                    ethernet = scapy.Ether(src='08:00:27:59:3d:4a', dst='08:00:27:08:9c:bd', type=0x0800)
                    scapy.sendp(ethernet / scapy.Raw(ip_pck), iface='enp0s10')
                    print('sent within _send_following_fragments')
                    self.offset = self.offset + ip_len
                else:
                    self.splitIP_head[sn] = (True, ip_pck)
                    # packet processed, time to remove it from dictionary
                    del self.dict[sn]
                    break


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

        # times when packets out of order are received
        self.lost_or_delayed = []

        # this dictionary allows to check fast if a spck received is a delayed one or not.
        # a loop through all the dictionary in the other threads will never be done thanks to
        # the presence of the list self.out_of_order_time
        self.delayed_spcks = {}  # element is tuple (if_delated, time_reception_following_pck)


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
        #ip_receiver = IP_Receiver("IP_Receiver-Thread", ip_buf, run_event)
        #ip_receiver.start()

        ip_receiver = Second_IP_Receiver("Second_IP_Receiver-Thread", ip_buf, run_event)
        ip_receiver.start()


        # only destination for now is SIG at 1-12
        dest_ia = ISD_AS().from_values(1, 12)
        dest_host = HostAddrIPv4('169.254.0.2')
        dest_port = 40500
        dest_sig_addr = SCIONAddr().from_values(dest_ia, dest_host)

        '''
        # only destination for now is SIG at 1-11
        dest_ia = ISD_AS().from_values(1, 11)
        dest_host = HostAddrIPv4('169.254.0.1')
        dest_port = 30100
        dest_sig_addr = SCIONAddr().from_values(dest_ia, dest_host)'''


        # create a SCION_Sender that processes all the IP's buffers, decides which one to has the priority
        # and forwards the SCION packets to respective the remote SIG
        scion_sender = SCION_Sender("SCION_Sender-Thread", api_addr, ip_buf, sig_addr, dest_sig_addr, dest_port, scion_sock, run_event, api=True)
        scion_sender.start()

        # splitIP_tail[sn] contains the last fragment of the last IP pck contained in SCION pck with SN-1
        self.splitIP_tail = {}
        # splitIP_head[sn] contains the first fragment of the last IP pck contained in SCION pck SN
        # or an intermediary fragment if index=0
        self.splitIP_head = {}


        # create socket for IP_Sender and Send_Delayed_Packets
        ICMP_CODE = socket.getprotobyname('icmp')
        ipsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

        # create IP_Sender
        ip_sender = IP_Sender("IP_Sender-Thread", self.spcks_dict, self.splitIP_tail, self.splitIP_head, ipsock, run_event)
        ip_sender.start()

        # create Flush_TimeArray thread
        delayed_pcks = Send_Delayed_Packets("Send_Delayed_Packets-Thread", self.spcks_dict, self.lost_or_delayed, self.delayed_spcks, self.splitIP_tail, self.splitIP_head, ipsock, run_event)
        delayed_pcks.start()

        # loop for SCION Receiver
        self._SCION_Receiver(run_event, scion_sock)


    def _SCION_Receiver(self, event, sock):

        self.sn_expected = 0
        try:
            while 1:
                self._encap_recv(sock)
                #self.sn_expected = (self.sn_expected + 1) % 4294967296

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
        #print('SCION pld received: ', spck)
        sn, index, unused, payload = self._unpack_scion_pck(spck)
        #print('SCION pld: ', payload)

        # if packets lost
        if sn != self.sn_expected:
            current_time = datetime.datetime.now()

            if (sn in self.delayed_spcks) and ((self.delayed_spcks[sn][1]-current_time).total_seconds() <= HALF_RTT):
                # delayed packet arrived in time. Store it
                self.spcks_dict[sn] = Decapsulated_Packet(sn, index, unused, payload)
                # print('added SCION pck with sn: %s and index: %s' % (sn, index))

                # print('************************************')

            elif not(sn in self.delayed_spcks):
                # the packets lost/delayed can be more than 1
                while(self.sn_expected <= sn):
                    print('packet with sn= %s was lost' % self.sn_expected)
                    self.lost_or_delayed.insert(0,(self.sn_expected, current_time))  # insert on the left ---> TO BE REMOVED USING pop()
                    self.delayed_spcks[self.sn_expected] = (True, current_time)

                    self.sn_expected = (self.sn_expected + 1)% 4294967296

                self.spcks_dict[sn] = Decapsulated_Packet(sn, index, unused, payload)
                # print('added SCION pck with sn: %s and index: %s' % (sn, index))

                # print('************************************')

                self.sn_expected = (self.sn_expected + 1) % 4294967296

        else:
            self.spcks_dict[sn] = Decapsulated_Packet(sn, index, unused, payload)
            # print('added SCION pck with sn: %s and index: %s' % (sn, index))

            # print('************************************')

            self.sn_expected = (self.sn_expected + 1) % 4294967296


    def _unpack_scion_pck(self, spck):
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


