# -*- coding: utf-8 -*-
import sys
from scapy.layers.dot11 import *
from scapy.layers.dot11 import Dot11, LLC, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp

ap_list = []                                #Lista de indices para controlar que paquetes nos han llegado
IFACE = 'wlx00c0caa4737b'                   #Interfaz de la targeta de red del transmisor
AP_MAC = ' 00:c0:ca:a4:73:7b'               #Direccion mac del transmisor
AP_MAC_2= '00:c0:ca:a4:73:7c'               #Direccion mac del receptor()

estand = sys.argv[1]
rates = sys.argv[2]

packet = []
if int(estand)==1:
    #############  IEEE 802.11 A 802.11a (54MBit/s 5GHz)
    print("Estandar Seleccionado 802.11 A")
    qoscontrol=b'\x00\x00'
    packet.append(RadioTap(present="Rate+Channel",Rate=int(rates),ChannelFlags="OFDM+5GHz") /
                      Dot11(type=2, subtype=8, addr1=AP_MAC_2, addr2=AP_MAC,addr3=AP_MAC)/ Dot11Beacon(cap="ESS+CFP") / Dot11Elt(ID='SSID', info="ap0") / Dot11Elt(ID='Supported Rates',
                                                                                        info="\x0c\x12\x18\x24\x30\x48\x60\x6c") /
              Dot11Elt(ID='DSSS Set', info=chr(56)))

elif int(estand) ==2:
    #############  IEEE 802.11 B 802.11b (11MBit/s 2.4GHz)
    print("Estandar Seleccionado 802.11 B")
    packet.append(RadioTap(present="Rate+Channel",Rate=float(rates),ChannelFlags="CCK+2GHz") /
                      Dot11(type=2, subtype=8, addr1=AP_MAC_2, addr2=AP_MAC,addr3=AP_MAC) / Dot11Beacon(cap="ESS+CFP") / Dot11Elt(ID='SSID', info="ap0") / Dot11Elt(ID='Supported Rates',
                                                                                        info="\x0c\x12\x18\x24\x30\x48\x60\x6c") /
              Dot11Elt(ID='DSSS Set', info=chr(56)))
elif int(estand) ==3:
    #############  IEEE 802.11 G
    print("Estandar Seleccionado 802.11 G")
    packet.append(RadioTap(present="Rate+Channel", Rate=float(rates), ChannelFlags="OFDM+2GHz") / Dot11(type=2, subtype=8, addr1=AP_MAC_2,
                                                                                    addr2=AP_MAC,
                                                                                    addr3=AP_MAC) /
                  Dot11Beacon(cap="ESS+CFP") / Dot11Elt(ID='SSID', info="ap0") / Dot11Elt(ID='Supported Rates',
                                                                                          info="\x0c\x12\x18\x24\x30\x48\x60\x6c") /
                  Dot11Elt(ID='DSSS Set', info=chr(56)))
elif int(estand) ==4:
#############  IEEE 802.11 N
    print("Estandar Seleccionado 802.11 N")
    packet.append(RadioTap(present="Channel+MCS", ChannelFlags="2GHz+Dynamic_CCK_OFDM",
                       knownMCS='MCS_bandwidth+MCS_index+guard_interval+STBC_streams',
                       MCS_bandwidth=0, MCS_index=int(rates), guard_interval=1, STBC_streams=0) / Dot11(type=2, subtype=8,
                                                                                               addr1=AP_MAC_2,
                                                                                               addr2=AP_MAC,
                                                                                               addr3=AP_MAC) /Dot11Beacon(cap="ESS+CFP") / Dot11Elt(ID='SSID', info="ap0") / Dot11Elt(ID='Supported Rates',
                                                                                        info="\x0c\x12\x18\x24\x30\x48\x60\x6c") /
              Dot11Elt(ID='DSSS Set', info=chr(56)))

sendp(packet, iface=IFACE, verbose=False)
exit()
