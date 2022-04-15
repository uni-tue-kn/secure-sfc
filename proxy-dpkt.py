#! /usr/bin/env python3

import socket
import threading
import dpkt
import os

from scapy.all import ETH_P_ALL
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from multiprocessing import Pipe, Process


def decrypt(dec_p_out, cache_p_in, aesKey, aesNonce, spi):
    while True:
        eth = dec_p_out.recv()
        ip = eth.data

        # parse ESP headers
        if not isinstance(ip.data, dpkt.esp.ESP):
            print('Non-ESP packet')
            continue
        esp = ip.data
        pktSPI = esp.spi.to_bytes(4, byteorder='big')
        pktSEQ = esp.seq.to_bytes(4, byteorder='big')
        if pktSPI != spi:
            print('Wrong SPI!')
            continue

        try:
            aesgcm = AESGCM(aesKey)
            decData = aesgcm.decrypt(aesNonce + bytes(esp.data[:8]), esp.data[8:], pktSPI + pktSEQ)
            nextHeader = int.from_bytes(decData[-1:], byteorder='big')
            padLength = int.from_bytes(decData[-2:-1], byteorder='big')
            payloadEnd = -2-padLength
            decData = decData[:payloadEnd]
        except InvalidTag:
            print('Invalid Tag!')
            continue

        # replace original IP packet with decrypted packet
        ip = dpkt.ip.IP(decData)
        eth.data = ip
        cache_p_in.send((eth, True))

def encrypt(enc_p_out, sockLo, aesKey, aesNonce, spi):
    while True:
        eth, labels = enc_p_out.recv()
        ip = eth.data

        aesgcm = AESGCM(aesKey)
        iv = os.urandom(8)

        seq = 1
        nextHeader = 4
        padLength = (len(bytes(eth.data))+2)%4
        if padLength == 0:
            data = bytes(eth.data)
        else:
            pad = 0
            data = bytes(eth.data) + pad.to_bytes(padLength, byteorder='big')
        
        data = data + padLength.to_bytes(1, byteorder='big') + nextHeader.to_bytes(1, byteorder='big')

        encData = aesgcm.encrypt(aesNonce + iv, data, spi + seq.to_bytes(4, byteorder='big'))
        encData = iv + encData
        esp = dpkt.esp.ESP(spi = int.from_bytes(spi, byteorder='big'), seq = seq)
        esp.data = encData
    
        ipOuter = dpkt.ip.IP(src = ip.src, dst = ip.dst, p = 50)
        ipOuter.data = bytes(esp)

        eth.data = ipOuter
            
        eth.mpls_labels = labels
        eth.type = 0x8847

        sockLo.send(bytes(eth))

def cache(cache_p_out, enc_p_in, sockOut):
    cache = dict()
    while True:
        eth, decrypted = cache_p_out.recv()

        ip = eth.data

        # parse TCP headers
        if not isinstance(ip.data, dpkt.tcp.TCP):
            print('Non-TCP packet')
            print(eth)
            continue
        tcp = ip.data

        key = str(ip.src) + str(ip.dst) + str(ip.id) + str(tcp.sport) + str(tcp.dport) + str(tcp.seq) + str(tcp.ack)

        if decrypted:
            cache[key] = eth.mpls_labels
            eth.mpls_labels = None
            eth.type = 0x0800
            eth.data = ip
            sockOut.send(bytes(eth))
        elif key in cache:
            labels = cache[key]
            del cache[key]
            enc_p_in.send((eth, labels))
        else:
            print('Cache miss')


key = bytes.fromhex('1234567890ABCDEF1234567890abcdef12345678')
aesKey = bytes(key[:-4])
aesNonce = bytes(key[-4:])
spi = bytes.fromhex('11111112')

sockIn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sockIn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
sockIn.bind(('proxyIn_2', ETH_P_ALL))

sockOut = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sockOut.bind(('proxyIn_1', 0))

sockLo = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sockLo.bind(('lo', 0))

enc_p_out, enc_p_in = Pipe(duplex=False)
dec_p_out, dec_p_in = Pipe(duplex=False)
cache_p_out, cache_p_in = Pipe(duplex=False)

enc_t = Process(target=encrypt, args=(enc_p_out, sockLo, aesKey, aesNonce, spi))
enc_t.start()

dec_t = Process(target=decrypt, args=(dec_p_out, cache_p_in, aesKey, aesNonce, spi))
dec_t.start()

cache_t = Process(target=cache, args=(cache_p_out, enc_p_in, sockOut))
cache_t.start()

print('Proxy started')

while True:
    pkt, sa_ll = sockIn.recvfrom(1500)
    if type == socket.PACKET_OUTGOING:
        continue
    if len(pkt) <= 0:
        break
    # ethertype = struct.unpack("!6s6sH", pkt[0:14])[2]
   
    # cache_p_in.send((pkt, ethertype))
    # cacheWorker.worker(pkt, ethertype, sockLo, sockOut)

    eth = dpkt.ethernet.Ethernet(pkt)
    eth.dst = b'\x00\x00\x00\x00\x00\x00'
    #print(eth.dst)
    #print(eth.mpls_labels)
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non-IP packet')
        continue
    # ip = eth.data

    ## MPLS in
    if eth.type == 0x8847:
        dec_p_in.send(eth)

    ## non-MPLS in
    else:
        cache_p_in.send((eth, False))        
