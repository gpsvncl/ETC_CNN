from collections import OrderedDict
# a-b
MICORSECOND = 1000000
def t_delta(time_a, time_b):
    delta = OrderedDict({})
    a_sec = time_a['seconds']
    b_sec = time_b['seconds']
    a_microsec = time_a['microseconds']
    b_microsec = time_b['microseconds']
    if a_microsec >= b_microsec:
        delta['sec_delta'] = a_sec - b_sec
        delta['microsec_delta'] = a_microsec - b_microsec
    else:
        a_sec -= 1
        delta['sec_delta'] = a_sec - b_sec
        delta['microsec_delta'] = MICORSECOND + a_microsec - b_microsec
    return delta
