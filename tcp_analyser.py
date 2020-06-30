from collections import OrderedDict
from binascii import hexlify, unhexlify
import dpkt
import datetime
import time
from collections import OrderedDict
from time_delta import t_delta

MAX_TCP_RETRANS_BUFFER = 10
MAX_PKT_NUM = 10000
PADDING_INT = 0

class Tcp_analyser:

    def __init__(self,session=False):
        self.session = session
        return

    def retrans_detected(self, record, seq_num, data_len):
        rc = 0
        if self.session == True and record['current_pkt_direction'] == '<':
            retrans_list = record['twin_tcp_retrans']
        else:
            retrans_list = record['tcp_retrans']
        #look for the sequence number in the stored array
        for retrans in retrans_list:
            if retrans['seq'] == seq_num:
                if retrans['len'] == data_len: 
                    rc = 1
                break
        return rc


    def flow_record_process (self, record, time_stamp, ip):
        
        # IPv6 is not supported now
        # if (type(ip) != dpkt.ip.IP and type(ip) != dpkt.ip6.IP6) or type(ip.data) != dpkt.tcp.TCP:
        if type(ip.data) != dpkt.tcp.TCP:
            return record
        #make sure we have room in the array 
        if record['pkt_num'] >= (MAX_PKT_NUM):
            return record  #no more room

        tcp = ip.data
        # if the payload > 0, store the sequence number and length into the retransmission buffer
        if len(tcp.data) > 0:
            retrans = {}
            retrans['seq'] = tcp.seq
            retrans['len'] = len(tcp.data)
            if self.session == True and record['current_pkt_direction'] == '<':
                if record['twin_tcp_retrans_tail'] <= MAX_TCP_RETRANS_BUFFER - 1:
                    # if retrans list is padded first time
                    if record['twin_tcp_retrans_flag'] == 0:
                        record['twin_tcp_retrans'].append(retrans)
                        record['twin_tcp_retrans_tail'] += 1
                    # if retrans list is padded not first time
                    else:
                        record['twin_tcp_retrans_tail'] += 1
                        if record['twin_tcp_retrans_tail'] <= MAX_TCP_RETRANS_BUFFER - 1:
                            record['twin_tcp_retrans'][record['twin_tcp_retrans_tail']] = retrans
                # retrans list is full
                else:
                    record['twin_tcp_retrans_tail'] = 0
                    record['twin_tcp_retrans_flag'] = 1
                    record['twin_tcp_retrans'][record['twin_tcp_retrans_tail']] = retrans
            else:
                if record['tcp_retrans_tail'] <= MAX_TCP_RETRANS_BUFFER - 1:
                    if record['tcp_retrans_flag'] == 0:
                        record['tcp_retrans'].append(retrans)
                        record['tcp_retrans_tail'] += 1
                    else:
                        record['tcp_retrans_tail'] += 1
                        if record['tcp_retrans_tail'] <= MAX_TCP_RETRANS_BUFFER - 1:
                            record['tcp_retrans'][record['tcp_retrans_tail']] = retrans
                else:
                    record['tcp_retrans_tail'] = 0
                    record['tcp_retrans_flag'] = 1
                    record['tcp_retrans'][record['tcp_retrans_tail']] = retrans


        record['pkt_num'] += 1
        pkt = OrderedDict({})
        if self.session == True:
            pkt['direction'] = record['current_pkt_direction']
        seconds = int(time.mktime(datetime.datetime.utcfromtimestamp(time_stamp).timetuple()))
        microseconds = datetime.datetime.utcfromtimestamp(time_stamp).microsecond
        pkt['time_stamp'] = OrderedDict({'seconds': seconds, 'microseconds': microseconds})
        pkt['data_len'] = len(tcp.data)
        pkt['ip_content'] = hexlify(ip.__bytes__()).decode()
        record['pkt_info'].append(pkt)

    def ip_tcp_map(self, record):
        start_time = record['start_time_stamp']

        pkt_num = 0
        pkt_map_list =[]
        pkt_map_list.append(record['flow_key'])
        for pkt in record['pkt_info']:
            if pkt_num >= MAX_PKT_NUM:
                break
            pkt_num += 1
            pkt_map = OrderedDict({})

            if self.session == True: 
                if pkt['direction'] == '>':
                    pkt_map['direction_forward'] = 1
                    pkt_map['direction_backward'] = 0
                    init_seq = record['init_seq']
                elif pkt['direction'] == '<':
                    pkt_map['direction_forward'] = 0
                    pkt_map['direction_backward'] = 1
                    init_seq = record['init_seq_backward']
            else:
                init_seq = record['init_seq']

            pkt_time = pkt['time_stamp']
            pkt_map['time'] = t_delta(pkt_time, start_time)
            pkt_map['data_len'] = pkt['data_len']
            
            # IP_header_map
            # Judge the IPv4 or IPv6
            if '.' in record['flow_key']['source_addr']:
                ip = dpkt.ip.IP(unhexlify(pkt['ip_content']))
                pkt_map['ip_len'] = ip.len
                pkt_map['ip_hlen'] = pkt_map['ip_len'] - len(ip.data)
                pkt_map['ip_tos'] = ip.tos
                pkt_map['ip_ttl'] = ip.ttl
            else:
                ip = dpkt.ip6.IP6(unhexlify(pkt['ip_content']))
                pkt_map['ip_len'] = len(ip)
                pkt_map['ip_hlen'] = pkt_map['ip_len'] - ip.plen
                pkt_map['ip_tos'] = ip.fc
                pkt_map['ip_ttl'] = ip.hlim
            tcp = ip.data

            #TCP_header_map
            pkt_map['th_seq'] = tcp.seq - init_seq
            pkt_map['4layer_hdr_len'] = len(tcp) - len(tcp.data)
            pkt_map['URG'] = (tcp.flags & dpkt.tcp.TH_URG)>>5
            pkt_map['PSH'] = (tcp.flags & dpkt.tcp.TH_PUSH)>>3
            pkt_map['RST'] = (tcp.flags & dpkt.tcp.TH_RST)>>2
            pkt_map['FIN'] = (tcp.flags & dpkt.tcp.TH_FIN)
            pkt_map['ACK'] = (tcp.flags & dpkt.tcp.TH_ACK)>>4
            pkt_map['SYN'] = (tcp.flags & dpkt.tcp.TH_SYN)>>1
            pkt_map['ECE'] = (tcp.flags & dpkt.tcp.TH_ECE)>>6
            pkt_map['CWR'] = (tcp.flags & dpkt.tcp.TH_CWR)>>7
            pkt_map['th_win'] = tcp.win
            pkt_map['th_urp'] = tcp.urp

            DATA_LEN = len(tcp.data)
            if DATA_LEN != 0:
                pkt_map['data'] = hexlify(tcp.data[:DATA_LEN]).decode()
            else:
                pkt_map['data'] = None
            pkt_map_list.append(pkt_map)

        return pkt_map_list
