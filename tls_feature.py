import copy
import struct
import binascii
from collections import OrderedDict
import dpkt
from dpkt.ssl import parse_variable_array
from dpkt.ssl import parse_extensions
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography import x509

TLS_HDR_LEN = 5#This is record header len

TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_ALERT = 21
TLS_CONTENT_APPLICATION_DATA = 23

def parse_extensions(buf):
    """
    Parse TLS extensions in passed buf. Returns an ordered list of extension tuples with
    ordinal extension type as first value and extension data as second value.
    Passed buf must start with the 2-byte extensions length TLV.
    http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    """
    extensions_length = struct.unpack('!H', buf[:2])[0]
    extensions = []

    pointer = 2
    while pointer < extensions_length:
        ext_type = struct.unpack('!H', buf[pointer:pointer+2])[0]
        pointer += 2
        ext_data, parsed = parse_variable_array(buf[pointer:], 2)
        if parsed == 0:
            extensions.append((ext_type, None))
        else:
            extensions.append((ext_type, binascii.hexlify(ext_data).decode()))
        pointer += parsed
    return extensions

class RecordHeader(dpkt.Packet):
    __hdr__ = (
        ('type', 'B', 0),
        ('version', 'H', 0),
        ('length', 'H', 0),
    )
    def __init__(self, *args, **kwargs):
        # parent constructor
        dpkt.Packet.__init__(self, *args, **kwargs)

class MessageHeader(dpkt.Packet):
    __hdr__ = (
        ('type', 'B', 0),
        ('length_bytes', '3s', 0),
        ('version', 'H', 0x0301),
        ('random', '32s', '\x00' * 32),
    )
    def __init__(self, *args, **kwargs):
        # parent constructor
        dpkt.Packet.__init__(self, *args, **kwargs)
        
    @property
    def length(self):
        return struct.unpack('!I', b'\x00' + self.length_bytes)[0]
        
def client_hello_parse(tls_handle, message):
    message_header = MessageHeader(message)
    message_data = message_header.data
    session_id, pointer = parse_variable_array(message_data,
                                               1)  # The pointer point where we have parsed the message data
    tls_handle['session_id'] = binascii.hexlify(session_id).decode()
    # Now we get the client cipher suites
    ciphersuites, parsed = parse_variable_array(message_data[pointer:], 2)
    pointer += parsed
    num_ciphersuites = int(len(ciphersuites) / 2)
    tls_handle['client_cipher_suite_list'] = []
    for i in range(num_ciphersuites):
        cipher_suite = struct.unpack('!H', ciphersuites[2 * i:2 * i + 2])[0]
        try:
            tls_handle['client_cipher_suite_list'].append(dpkt.ssl_ciphersuites.BY_CODE[cipher_suite].name)
        except:
            tls_handle['client_cipher_suite_list'].append('Dpkt not support')
    # Now we get the compression_methods,TODO but the parse will be done later.
    compression_methods, parsed = parse_variable_array(
        message_data[pointer:], 1)
    tls_handle['compression_methods'] = binascii.hexlify(compression_methods).decode()
    pointer += parsed
    num_compression_methods = parsed - 1
    if len(message_data[pointer:]) >= 6:# 6 is right? The value 6 is used in dpkt.ssl.parse_extensions, so we follow it.
        extensions = parse_extensions(message_data[pointer:])
        tls_handle['client_extensions'] = extensions

def certificate_parse(tls_handle, message):
    handshake = dpkt.ssl.TLSHandshake(message)
    if len(handshake.data.certificates) == 0:
        tls_handle['certs_list'] = None
    else:
        tls_handle['certs_list'] = OrderedDict({})
        tls_handle['certs_list']['certs_cnt'] = len(handshake.data.certificates)
        tls_handle['certs_list']['list'] = OrderedDict({})
        for index in range(len(handshake.data.certificates)):
            cert_index = 'cert' + str(index)
            tls_handle['certs_list']['list'][cert_index] = OrderedDict({})
            cert_t = handshake.data.certificates[index]
            data_type = crypto.FILETYPE_ASN1
            # Transfer data type
            X509 = crypto.load_certificate(data_type, cert_t)
            X509_cryptography = X509.to_cryptography()
            tls_handle['certs_list']['list'][cert_index]['version'] = str(X509_cryptography.version)
            tls_handle['certs_list']['list'][cert_index]['serial_number'] = X509_cryptography.serial_number
            tls_handle['certs_list']['list'][cert_index]['valid_start'] = X509_cryptography.not_valid_before.strftime(
                '%Y/%m/%d-%H:%M:%S')
            tls_handle['certs_list']['list'][cert_index]['valid_end'] = X509_cryptography.not_valid_after.strftime(
                '%Y/%m/%d-%H:%M:%S')
            tls_handle['certs_list']['list'][cert_index]['public_key'] = (
                X509_cryptography.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()).replace(
                '\n', '')
            tls_handle['certs_list']['list'][cert_index]['issuer'] = X509_cryptography.issuer.rfc4514_string()
            tls_handle['certs_list']['list'][cert_index]['subject'] = X509_cryptography.subject.rfc4514_string()
            tls_handle['certs_list']['list'][cert_index][
                'signature_algorithm'] = X509_cryptography.signature_algorithm_oid._name
            tls_handle['certs_list']['list'][cert_index]['signature'] = binascii.hexlify(
                X509_cryptography.signature).decode()
            if len(X509_cryptography.extensions) == 0:
                tls_handle['certs_list']['list'][cert_index]['extensions_list'] = None
            else:
                tls_handle['certs_list']['list'][cert_index]['extensions_list'] = OrderedDict({})
                for i in range(len(X509_cryptography.extensions)):
                    ext_index = 'ext' + str(i)
                    if ((X509_cryptography.extensions[i]).oid._name) == 'subjectAltName':
                        ext = (X509_cryptography.extensions[i])
                        tls_handle['certs_list']['list'][cert_index]['extensions_list'][
                            ext_index] = ext.value.get_values_for_type(x509.DNSName)
                    # TODO many other extension type

#Shift through handshake data processing any messages that are encountered
def tls_handshake_buffer_parse(tls_handle):
    data = tls_handle['handshake_buffer']
    data_len = tls_handle['handshake_length']
    if data_len == 0:
        return
    while data_len > 0:
        record_header = RecordHeader(data)
        tls_len = record_header.length
        if record_header.type == 22:#handshake
            data = data[TLS_HDR_LEN:]
            data_len -= TLS_HDR_LEN
            if data[0] < 16:#dpkt can't support other type
                if data[0] == 1:#Client_hello
                    client_hello_parse(tls_handle, data)
                if data[0] == 2:#Server_hello
                    handshake = dpkt.ssl.TLSHandshake(data)
                    try:
                        tls_handle['server_cipher_suite'] = dpkt.ssl_ciphersuites.BY_CODE[handshake.data.cipher_suite].name
                    except:
                        tls_handle['server_cipher_suite'] = 'Dpkt not support'
                elif data[0] == 11:#Certificate
                    certificate_parse(tls_handle, data)
                data = data[tls_len:]
                data_len -= tls_len
            else:
                break
        elif record_header.type == 22 or record_header.type == 21 or record_header.type == 23:
            data = data[TLS_HDR_LEN + tls_len:]
            data_len -= TLS_HDR_LEN + tls_len
        else:
            break


def tls_update(payload, payload_len, tls_handle):
    rem_len = payload_len
    if (payload_len == 0):
        return
    if (tls_handle['done_handshake'] == 1):
        #We just need the handshake data
        return

    if tls_handle['done_handshake'] == 0:
        # Add Handshake (whole packet) data to the buffer for later usage.
        # This may be segmented data i.e. doesn't contain the start of message in this packet.
        ##print(content_type)
        payload_copy = bytes(copy.deepcopy(bytearray(payload)))
        tls_handle['handshake_buffer'] += payload_copy
        tls_handle['handshake_length'] += payload_len

    if (tls_handle['seg_offset']):
        if (tls_handle['seg_offset'] > payload_len):
            # The original message spans at least one more packet.
            tls_handle['seg_offset'] -= payload_len
            return
        payload = payload[tls_handle['seg_offset']:]
        rem_len -= tls_handle['seg_offset']
        tls_handle['seg_offset'] = 0

    while rem_len > 0:
        record_header = RecordHeader(payload)
        msg_len = record_header.length
        content_type = record_header.type
        if (msg_len > rem_len):
            tls_handle['seg_offset'] = msg_len - (rem_len - TLS_HDR_LEN)
        if (tls_handle['done_handshake'] == 0 and len(tls_handle['handshake_buffer']) and
        ( content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC or
        content_type == TLS_CONTENT_ALERT or
        content_type == TLS_CONTENT_APPLICATION_DATA )):
            # After the handshake phase.
            tls_handshake_buffer_parse(tls_handle)
            tls_handle['handshake_buffer'] = b''
            tls_handle['handshake_length'] = 0
            tls_handle['done_handshake'] = 1
        if tls_handle['seg_offset'] == 0:
            # Skip to the next message
            rem_len -= msg_len + TLS_HDR_LEN
            payload = payload[msg_len + TLS_HDR_LEN:]
        else:
            # The message has been segmented,this makes it skip out the loop while
            rem_len -= msg_len + TLS_HDR_LEN
    return

