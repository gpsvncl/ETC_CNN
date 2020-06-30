import os
import sys
import dpkt
import json
import pcap
import socket
from collections import OrderedDict
from tcp_analyser import Tcp_analyser
from udp_analyser import Udp_analyser
from others_analyser import Others_analyser
from binascii import hexlify, unhexlify
import datetime
import time


class Flow_Analyser:

    def __init__(self, session=False, output=None, map=False):
        self.active_flow_list ={}
        self.tcp_analyser = Tcp_analyser(session)
        self.udp_analyser = Udp_analyser(session)
        self.others_analyser = Others_analyser(session)
        self.map = map
        self.session = session
        if output == None:
            self.out_file_pointer = None
        elif output == sys.stdout:
            self.out_file_pointer = sys.stdout
        else:
            if os.path.exists(output):
                os.remove(output)
            self.out_file_pointer = open(output, 'w')


    def extract_flow_record(self, input_files):
        for input_file in input_files:
            if os.path.isfile(input_file):
                f = open(input_file, 'rb')
                if input_file.endswith('.pcap'):
                    try:
                        packets = dpkt.pcap.Reader(f)
                    except:
                        print('dpkt error')
                        continue
                elif input_file.endswith('.pcapng'):
                    packets = dpkt.pcapng.Reader(f)
                capture_type = 'offline'
            #TODO The online modules has not been accomplished.
            else:
                packets = pcap.pcap(input_file, timeout_ms=1000)
                capture_type = 'online'

            data_list = OrderedDict({})
            datalink_value = packets.datalink()  # get the pcap linktype
            while True:
                if capture_type == 'offline':
                    pkts = []
                    if type(packets) == dpkt.pcap.Reader:
                        while True:
                            try:
                                # Process the next pkt
                                pkts.append(packets.__next__())
                            except Exception as e:
                                break
                    elif type(packets) == dpkt.pcapng.Reader:
                        while True:
                            try:
                                pkts.append(packets.next())
                            except Exception as e:
                                break
                    f.close()

                else:
                    pkts = packets.readpkts()

                for ts, buf in pkts:
                    if datalink_value == 1:# This is the ethernet packet
                        try:
                            eth = dpkt.ethernet.Ethernet(buf)
                            ip = eth.data
                        except:
                            break
                    elif datalink_value == 101:# This is the raw_packet, which has no ethernet layer
                        try:
                            # Now only ipv4 support
                            ip = dpkt.ip.IP(buf)
                        except:
                            break

                    if type(ip) != dpkt.ip.IP and type(ip) != dpkt.ip6.IP6:# Don't handle the packet that haven't the ip layer
                        continue

                    lay_four = ip.data

                    if type(ip) == dpkt.ip.IP:
                        add_fam = socket.AF_INET
                    else:
                        add_fam = socket.AF_INET6
                    # Handle the packet
                    if type(lay_four) == dpkt.tcp.TCP:# packet is TCP
                        flow_key = (
                            socket.inet_ntop(add_fam,ip.src), lay_four.sport, socket.inet_ntop(add_fam,ip.dst),
                            lay_four.dport)
                        twin_flow_key = (
                            socket.inet_ntop(add_fam,ip.dst), lay_four.dport, socket.inet_ntop(add_fam,ip.src),
                            lay_four.sport)
                    elif type(lay_four) == dpkt.udp.UDP:# packet is UDP
                        flow_key = (
                            socket.inet_ntop(add_fam, ip.src), lay_four.sport, socket.inet_ntop(add_fam, ip.dst),
                            lay_four.dport)
                        twin_flow_key = (
                            socket.inet_ntop(add_fam, ip.dst), lay_four.dport, socket.inet_ntop(add_fam, ip.src),
                            lay_four.sport)
                    else:#This is the other situation, now we just support icmp
                        flow_key = (
                            socket.inet_ntop(add_fam, ip.src), ip.p, socket.inet_ntop(add_fam, ip.dst), ip.p)
                        twin_flow_key = (
                            socket.inet_ntop(add_fam, ip.dst), ip.p, socket.inet_ntop(add_fam, ip.src), ip.p)

                    data_len = len(lay_four.data)

                    try:
                        # Find if the flow_key is in the dictionary
                        # If not in ,goto except.
                        record = data_list[flow_key]
                        if self.session == True:
                            record['current_pkt_direction'] = '>'
                    except:
                        try:
                            if self.session == True:
                                # If there is no flow_key in the dictionary, find the key of the twin.
                                # If there is no twin_flow_key in dictionary, the exception happen and we should create a new flow in the dictionary.
                                record = data_list[twin_flow_key]
                                record['current_pkt_direction'] = '<'
                                if type(lay_four) == dpkt.tcp.TCP:
                                    if record['init_seq_backward'] == 0:
                                        record['init_seq_backward'] = lay_four.seq
                                else:#the other situation hasn't the seq number
                                    record['init_seq_backward'] = 0
                            else:
                                raise Exception
                        except:
                            flow_key_ = OrderedDict({})
                            flow_key_['source_addr'] = socket.inet_ntop(add_fam, ip.src)
                            flow_key_['dest_addr'] = socket.inet_ntop(add_fam, ip.dst)
                            flow = OrderedDict({})
                            # create a new flow record and init it
                            flow['pkt_num'] = 0
                            flow['pkt_info'] = []
                            seconds = int(time.mktime(datetime.datetime.utcfromtimestamp(ts).timetuple()))
                            microseconds = datetime.datetime.utcfromtimestamp(ts).microsecond
                            flow['start_time_stamp'] = OrderedDict({'seconds': seconds, 'microseconds': microseconds})
                            flow['init_seq_backward'] = 0
                            #process tcp packet
                            if type(lay_four) == dpkt.tcp.TCP:
                                flow_key_['source_port'] = lay_four.sport
                                flow_key_['dest_port'] = lay_four.dport
                                flow_key_['protocol'] = 'TCP'
                                flow['flow_key'] = flow_key_
                                flow['init_seq'] = lay_four.seq
                                flow['tcp_retrans'] = []
                                flow['tcp_retrans_flag'] = 0#Whether the retrans list padded first time
                                flow['tcp_retrans_tail'] = 0
                                # add the new record into data_list
                                data_list[flow_key] = flow
                                record = data_list[flow_key]
                                if self.session == True:
                                    flow['twin_tcp_retrans'] = []
                                    flow['twin_tcp_retrans_flag'] = 0
                                    flow['twin_tcp_retrans_tail'] = 0
                                    record['current_pkt_direction'] = '>'
                            #process udp packet
                            elif type(lay_four) == dpkt.udp.UDP:
                                flow_key_['source_port'] = lay_four.sport
                                flow_key_['dest_port'] = lay_four.dport
                                flow_key_['protocol'] = 'UDP'
                                flow['flow_key'] = flow_key_
                                flow['init_seq'] = 0
                                # add the new record into data_list
                                data_list[flow_key] = flow
                                record = data_list[flow_key]
                                if self.session == True:
                                    record['current_pkt_direction'] = '>'
                            #process other non-tcp and non-udp packet
                            else:
                                flow_key_['source_port'] = ip.p # The ip protocol in layer3
                                flow_key_['dest_port'] = ip.p
                                flow_key_['protocol'] = 'Others'
                                flow['flow_key'] = flow_key_
                                flow['init_seq'] = 0
                                # add the new record into data_list
                                data_list[flow_key] = flow
                                record = data_list[flow_key]
                                if self.session == True:
                                    record['current_pkt_direction'] = '>'
                    #Process the payload of the packet
                    if type(lay_four) == dpkt.tcp.TCP:
                        rc = 0
                        if data_len > 0:
                            rc = self.tcp_analyser.retrans_detected(record, lay_four.seq, data_len)
                        if rc != 0:  # the packet is retransmission,ignore the packet
                            continue
                        if data_len > 0:
                            self.tcp_analyser.flow_record_process(record, ts, ip)
                    elif type(lay_four) == dpkt.udp.UDP:
                        if data_len > 0:
                            self.udp_analyser.flow_record_process(record, ts, ip)
                    else:
                        if data_len > 0:
                            self.others_analyser.flow_record_process(record, ts, ip)

                if len(data_list) and self.out_file_pointer != None:
                    self.write_record(data_list)
                if capture_type == 'offline':
                    break

        if self.out_file_pointer != None and self.out_file_pointer != sys.stdout:
            self.out_file_pointer.close()

    def write_record(self, record_data):

        #xl map
        if self.map == True:
            for rec_value in record_data.values():
                if rec_value['pkt_num'] >= 10:
                    if rec_value['flow_key']['protocol'] == 'TCP':
                        pkts_map = self.tcp_analyser.ip_tcp_map(rec_value)
                        if len(pkts_map) == 0:
                            continue
                        self.out_file_pointer.write('%s\n' % json.dumps(pkts_map))
                        self.out_file_pointer.flush()
                    elif rec_value['flow_key']['protocol'] == 'UDP':
                        pkts_map = self.udp_analyser.ip_udp_map(rec_value)
                        if len(pkts_map) == 0:
                            continue
                        self.out_file_pointer.write('%s\n' % json.dumps(pkts_map))
                        self.out_file_pointer.flush()
                    else:
                        pkts_map = self.others_analyser.ip_others_map(rec_value)
                        if len(pkts_map) == 0:
                            continue
                        self.out_file_pointer.write('%s\n' % json.dumps(pkts_map))
                        self.out_file_pointer.flush()
            return

        #simple parse output, you can do your analysis in your view according to the output, this may be desperated in the future.
        for rec_value in record_data.values():
            try:
                if rec_value['flow_key']['protocol'] == 'TCP':
                    del rec_value['tcp_retrans']
                if self.session == True:
                    if rec_value['flow_key']['protocol'] == 'TCP':
                        del rec_value['twin_tcp_retrans']
                    del rec_value['current_pkt_direction']
            except:
                pass
            self.out_file_pointer.write('%s\n' % json.dumps(rec_value))
            self.out_file_pointer.flush()


