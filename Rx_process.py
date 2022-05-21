#!/usr/bin/env python
# import scapy module
import sys
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Elt, Dot11EltHTCapabilities, Dot11AssoReq
from scapy.sendrecv import sendp
from Generatramas import *
from Criptotramas import *
from datos import *

AP_MAC_2 = '00:c0:ca:a4:73:7c'
AP_MAC = '00:c0:ca:a4:73:7b'
ap_list = []
IFACE2="wlx00c0caa4737c"
rate=0
key = b'\x01\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a'
ps = [1100645304239144332874899719259313845702512851699, 1100645304239144332874899719259330726252929972829,
      18465764008605840127818093568353291822549225699331595729]  # Claves p
xs = [469185440907188674086266365887713402920751416175, 469185440907188674086266365887713402920751416175,
      7016009363412435780763082007262025939147461935248010908]  # Claves x
Hdr = 15954397600484676080445144553223529992678013943537230069224121000855699303061777531981089406222510881421088752704688036147253082732657897862191895053631674856772128322391273493214154863018969779796561231280601263793302777253129776032382760813815413222441888256216530367314241202928278526289479100743111536202


def PacketHandler(pkt):
    # Capturamos el AMPDU
    #print("tipo",pkt.subtype)
    if pkt.type == 2 and pkt.subtype == 8 and pkt.addr1==AP_MAC_2:
        if pkt.subtype not in ap_list:
            ap_list.append(pkt.subtype)
            ver=pkt.getlayer(Dot11)
            print("LONGITUD ENTRADA RADIO",len(ver))
            print(ver)
            n=0
            numero=int.from_bytes(ver, byteorder='big')
            hexa=numero.to_bytes((numero.bit_length() + 7) // 8, byteorder='big')
            print("LONGITUD conversion entrada", len(hexa))
            AMPDU_FINAL = b''
            for i in hexa:
                #print(hex(i))
                if n<(len(hexa)-4) and n>=24:
                    if i != 0:
                        by = i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')
                        AMPDU_FINAL = AMPDU_FINAL + by
                    else:
                        AMPDU_FINAL = AMPDU_FINAL + b'\x00'

                n = n + 1
            intAMPDUfinal=int.from_bytes(AMPDU_FINAL, byteorder='big')
            if int(forma) == 1 :
            #print("Longitud AMPDU_FINAL",len(AMPDU_FINAL))
                print("AMSDU CIFRADO", AMPDU_FINAL)
                MSDU, lapso = AMPDU_dec(intAMPDUfinal, key)
                descifrado = MSDU[0].to_bytes((MSDU[0].bit_length() + 7) // 8, byteorder='big')
                print("AMSDU DESCIFRADO", descifrado)
            if int(forma) == 2:
                MSDUs = AMSDU_dec(Hdr, intAMPDUfinal, ps, xs)
                for i in MSDUs:
                    print(i)
            exit()
            #MSDU, lapso = AMPDU_dec(int.from_bytes(ver, byteorder='big'), key)


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

rate = sys.argv[1]
forma= sys.argv[2]

scapy.sniff(iface=IFACE2, prn=PacketHandler, timeout=30000)
