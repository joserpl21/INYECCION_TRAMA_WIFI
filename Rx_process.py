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
rate=0
key = b'\x01\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a'

def PacketHandler(pkt):
    # Capturamos el AMPDU
    #print("tipo",pkt.subtype)
    if pkt.type == 0 and pkt.subtype == 15:
        if pkt.subtype not in ap_list:
            ap_list.append(pkt.subtype)

            ver=pkt.getlayer(Dot11)
            print(ver)

            #MSDU, lapso = AMPDU_dec(int.from_bytes(ver, byteorder='big'), key)

            exit()
            #print(pkt)
            intAMPDU=int.from_bytes(pkt, byteorder='big')
            print(intAMPDU)

            MSDU, lapso = AMPDU_dec(intAMPDU, key)
            descifrado = MSDU[0].to_bytes((MSDU[0].bit_length() + 7) // 8, byteorder='big')
            print("Descifrado PDU", descifrado)

    #Capturamos el ADDBA Request
    if pkt.type == 0 and pkt.subtype == 13:
        if pkt.subtype not in ap_list:
            if pkt.addr2 == AP_MAC:
                ap_list.append(pkt.subtype)
                # Paquete ADDBA Response
                packet = []
                data = "\x03\x01\x01\x00\x00\x00\x00\x00\x00"
                packet.append(RadioTap(present='Rate',Rate=int(rate)) / Dot11(subtype=13, addr1=pkt.addr2, addr2=AP_MAC_2, addr3=AP_MAC_2) / data)
                sendp(packet, iface=IFACE2, verbose=False)
                print("Envio correcto ADDBA Response")

    #Capturamos el Block ACK request enviado por el AP
    if pkt.type == 1 and pkt.subtype == 8:
        if pkt.subtype not in ap_list:
            if pkt.addr2== AP_MAC:
                ap_list.append(18)
                #Paquete Block ACK
                packet = []
                data = "\x05\x00\xb0\x03\x00\x00\x00\x00\x00\x00\x00\x00"
                packet.append(
                    RadioTap(present='Rate',Rate=int(rate)) / Dot11(type=1, subtype=9, addr1=pkt.addr2, addr2=AP_MAC_2, addr3=AP_MAC_2) / data)
                sendp(packet, iface=IFACE2, verbose=False)
                print("Envio correcto Block ACK")

    #Capturamos el Probe response enviado por el AP
    if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 5:
        if pkt.subtype not in ap_list:
            infoPacket=pkt.getlayer(Dot11Elt)
            if infoPacket.info.decode() =="ap0":
                ap_list.append(pkt.subtype)
                packet = []

                packet.append(RadioTap(present='Rate',Rate=int(rate)) / Dot11(subtype=0, addr1=pkt.addr3, addr2=AP_MAC_2, addr3=AP_MAC_2)/Dot11AssoReq(cap="ESS+CFP+res14")/ Dot11Elt(ID='SSID', info=infoPacket.info.decode()) / Dot11Elt(ID='Supported Rates', info="\x82\x84\x8b\x0c\x12\x96\x18\x24") /
        Dot11Elt(ID='DSSS Set', info=chr(56)) / Dot11EltHTCapabilities(SM_Power_Save=3,
                                                                       Short_GI_20Mhz=1, Tx_STBC=1,
                                                                       Rx_STBC=1, Max_A_MSDU=1,
                                                                       DSSS_CCK=1))

                sendp(packet, iface=IFACE2, verbose=False)
                print("Envio correcto Association request")


    #Capturamos el BEACON enviado por el AP
    if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 8:
        if pkt.subtype not in ap_list:
            infoBeacon = pkt.getlayer(Dot11Elt)
            # Paquete Probe Request
            if infoBeacon.info.decode() == "ap0":
                ap_list.append(0)
                packet = []
                packet.append(
                    RadioTap(present='Rate', Rate=18) / Dot11(subtype=4, addr1='ff:ff:ff:ff:ff:ff', addr2=AP_MAC_2,
                                                             addr3=AP_MAC_2) / Dot11Elt(
                        ID='SSID',
                        info=infoBeacon.info) /
                    Dot11Elt(ID='Supported Rates', info="\x82\x84\x8b\x0c\x12\x96\x18\x24") /
                    Dot11Elt(ID='Extended Supported Rates', info="\xb0\x48\x60\x6c"))
                # Enviamos el Probe request
                sendp(packet, iface=IFACE2, verbose=False)
                print("Envio correcto Probe request")

rate=sys.argv[1]
print(rate)
scapy.sniff(iface=IFACE2, prn=PacketHandler, timeout=30000)
