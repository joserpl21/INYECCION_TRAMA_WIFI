#!/usr/bin/env python
# import scapy module
import sys
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Elt, Dot11EltHTCapabilities, Dot11AssoReq
from scapy.sendrecv import sendp
from Generatramas import *
from Criptotramas import *

AP_MAC_2 = '00:c0:ca:a4:73:7c'
AP_MAC = '00:c0:ca:a4:73:7b'
ap_list = []
IFACE2="wlx00c0caa4737c"
def PacketHandler(pkt):
    # Capturamos el AMPDU
    #print("tipo",pkt.subtype)
    if pkt.addr1==AP_MAC_2:
        print(pkt.show())
        ap_list.append(pkt.subtype)
        ver = pkt.getlayer(Dot11)
        numero = int.from_bytes(ver, byteorder='big')
        hexa = numero.to_bytes((numero.bit_length() + 7) // 8, byteorder='big')
        print(hexdump(hexa))

scapy.sniff(iface=IFACE2, prn=PacketHandler, timeout=30000)
