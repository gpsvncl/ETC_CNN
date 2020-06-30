from collections import OrderedDict
from binascii import hexlify, unhexlify
import dpkt
import datetime
import time
from time_delta import t_delta

MAX_PKT_NUM = 10000
PADDING_INT = 0


class Others_analyser:

    def __init__(self, session=False):
        self.session = session
        return

    def flow_record_process(self, record, time_stamp, ip):

        # make sure we have room in the array
        if record['pkt_num'] >= MAX_PKT_NUM:
            return record  # no more room

        other = ip.data

        record['pkt_num'] += 1
        pkt = OrderedDict({})
        if self.session == True:
            pkt['direction'] = record['current_pkt_direction']
        seconds = int(time.mktime(datetime.datetime.utcfromtimestamp(time_stamp).timetuple()))
        microseconds = datetime.datetime.utcfromtimestamp(time_stamp).microsecond
        pkt['time_stamp'] = OrderedDict({'seconds': seconds, 'microseconds': microseconds})
        pkt['data_len'] = len(other)
        pkt['ip_content'] = hexlify(ip.__bytes__()).decode()
        record['pkt_info'].append(pkt)

    def ip_others_map(self, record):
        start_time = record['start_time_stamp']

        pkt_num = 0
        pkt_map_list = []
        pkt_map_list.append(record['flow_key'])
        for pkt in record['pkt_info']:
            if pkt_num >= MAX_PKT_NUM:#is there the code is redundant
                break
            pkt_num += 1
            pkt_map = OrderedDict({})

            if self.session == True:
                if pkt['direction'] == '>':
                    pkt_map['direction_forward'] = 1
                    pkt_map['direction_backward'] = 0
                elif pkt['direction'] == '<':
                    pkt_map['direction_forward'] = 0
                    pkt_map['direction_backward'] = 1

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

            # other_header_map,because of there is no information in other_header,
            # so the variation of the header information is 0
            pkt_map['th_seq'] = PADDING_INT
            pkt_map['4layer_hdr_len'] = PADDING_INT
            pkt_map['URG'] = PADDING_INT
            pkt_map['PSH'] = PADDING_INT
            pkt_map['RST'] = PADDING_INT
            pkt_map['FIN'] = PADDING_INT
            pkt_map['ACK'] = PADDING_INT
            pkt_map['SYN'] = PADDING_INT
            pkt_map['ECE'] = PADDING_INT
            pkt_map['CWR'] = PADDING_INT
            pkt_map['th_win'] = PADDING_INT
            pkt_map['th_urp'] = PADDING_INT

            print("Others ip protocol, please parsing by yourself using dpkt")
            DATA_LEN = len(ip.data)  # some others
            pkt_map['data'] = "Others ip protocol, please parsing by yourself using dpkt"
            pkt_map_list.append(pkt_map)

        return pkt_map_list
