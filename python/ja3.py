#!/usr/bin/env python
"""Generate JA3 fingerprints from PCAPs using Python."""

import argparse
import dpkt
import json
import socket
import binascii
import struct
import os
from hashlib import md5

__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.0"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings2@gmail.com"


GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22


def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def process_pcap():
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    
    data = bytes([22, 3, 1, 0, 201, 1, 0, 0, 197, 3, 3, 82, 50, 235, 232, 231, 181, 243, 122, 13, 113, 213, 238, 184, 242, 230, 164, 189, 148, 5, 55, 17, 170, 189, 193, 212, 189, 211, 11, 239, 192, 39, 240, 0, 0, 36, 192, 48, 192, 44, 192, 47, 192, 43, 192, 20, 192, 10, 192, 19, 192, 9, 0, 159, 0, 158, 0, 57, 0, 51, 0, 157, 0, 156, 0, 53, 0, 47, 0, 10, 0, 255, 1, 0, 0, 120, 0, 0, 0, 18, 0, 16, 0, 0, 13, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 46, 99, 104, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 28, 0, 26, 0, 23, 0, 25, 0, 28, 0, 27, 0, 24, 0, 26, 0, 22, 0, 14, 0, 13, 0, 11, 0, 12, 0, 9, 0, 10, 0, 35, 0, 0, 0, 13, 0, 32, 0, 30, 6, 1, 6, 2, 6, 3, 5, 1, 5, 2, 5, 3, 4, 1, 4, 2, 4, 3, 3, 1, 3, 2, 3, 3, 2, 1, 2, 2, 2, 3, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 15, 0, 1, 1, 51, 116, 0, 0])
   
    if len(data) <= 0:
        pass

    tls_handshake = bytearray(data)
    if tls_handshake[0] != TLS_HANDSHAKE:
        pass

    records = list()

    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(data)
    except dpkt.ssl.SSL3Exception:
        pass
    except dpkt.dpkt.NeedData:
        pass

    if len(records) <= 0:
        pass

    for record in records:
        if record.type != TLS_HANDSHAKE:
            continue
        if len(record.data) == 0:
            continue
        client_hello = bytearray(record.data)
        if client_hello[0] != 1:
            # We only want client HELLO
            continue
        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except dpkt.dpkt.NeedData:
            # Looking for a handshake here
            continue
        if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
            # Still not the HELLO
            continue

        client_handshake = handshake.data
        buf, ptr = parse_variable_array(client_handshake.data, 1)
        buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
        ja3 = [str(client_handshake.version)]

        # Cipher Suites (16 bit values)
        ja3.append(convert_to_ja3_segment(buf, 2))
        ja3 += process_extensions(client_handshake)
        ja3 = ",".join(ja3)

        record = {
                    "ja3": ja3,
                    "ja3_digest": md5(ja3.encode()).hexdigest(),
                    "client_hello_pkt": binascii.hexlify(data).decode('utf-8')}
    results = record

    return results


def main():
    
    output = process_pcap()

   
    print("ja3:", output["ja3"])
    print("ja3_digest:", output["ja3_digest"])
if __name__ == "__main__":
        main()
