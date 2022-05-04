from scapy.layers.dot11 import *
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, LLC, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from scapy.layers.inet import UDP
from scapy.packet import Raw
from scapy.utils import hexdump

ap_list = []
IFACE = 'wlx00c0caa4737c'
AP_MAC = ' 00:c0:ca:a4:73:7c'
AP_MAC_2= '00:c0:ca:a4:73:7b'

def PacketHandler(pkt):
    # Capturamos el Assoc request
    if pkt.subtype == 0:
        if pkt.subtype not in ap_list:
            infoPacket = pkt.getlayer(Dot11Elt)
            if infoPacket.info.decode()=="ap0":
                ap_list.append(pkt.subtype)
                packet=[]
                packet.append(RadioTap() / Dot11(subtype=1, addr1=pkt.addr2, addr2=AP_MAC, addr3=AP_MAC) / Dot11AssoResp(cap="ESS+CFP") /
                               Dot11Elt(ID='SSID', info=infoPacket.info.decode()) / Dot11Elt(ID='Supported Rates',
                                                                          info="\x82\x84\x8b\x0c\x12\x96\x18\x24") /
                               Dot11Elt(ID='DSSS Set', info=chr(56)) / Dot11EltHTCapabilities(SM_Power_Save=3,
                                                                                              Short_GI_20Mhz=1, Tx_STBC=1,
                                                                                              Rx_STBC=1, Max_A_MSDU=1,
                                                                                              DSSS_CCK=1)
                               / Dot11Elt(ID='Extended Supported Rates', info="\xb0\x48\x60\x6c"))
                sendp(packet, iface=IFACE, verbose=False)
                print("Enviado Association response")
                # Paquete ADDBA Request
                packet = []
                data = "\x03\x00\x01\x00\x10\x00\x00\x03\x0a"
                data2 = "\x00\x03\x61\x70\x30"
                packet.append(RadioTap() / Dot11(subtype=13, addr1=pkt.addr3, addr2=AP_MAC, addr3=AP_MAC) / data / Dot11Elt(ID='SSID', info=infoPacket.info.decode()))
                sendp(packet, iface=IFACE, verbose=False)
                print("Enviado correctamente ADDBA Request..")

    #Capturamos el ADDBA Response
    if pkt.type==0 and pkt.subtype == 13:
        if pkt.subtype not in ap_list:
            if pkt.addr2==AP_MAC_2:
                ap_list.append(pkt.subtype)
                # Paquete AMPDU SIMPLE
                """packet = []
                data = "\x01\x01\x00\x11"
                packet.append(RadioTap() / Dot11(subtype=4, addr1=pkt.addr2, addr2=AP_MAC, addr3=AP_MAC, FCfield="MF") / data)
                sendp(packet, iface=IFACE, verbose=False)"""
                lengthMSDU = b'\x04\x00'
                org = b'\x00\x00\x00\x08\x00'
                ip = IP(len=32, id=41777, flags="DF", frag=0, ttl=64, proto=2, src="10.3.17.88", dst="10.3.17.90")
                udp = UDP(sport=5201, dport=52908, len=12)
                dataPDU1 = b'\x01'
                dataPDU2 = b'\x02'
                packet_msdu1 = ip / udp / dataPDU1
                packet_msdu2 = ip / udp / dataPDU2
                packet = []
                #packet.append(RadioTap() / Dot11(type=2, subtype=8, FCfield="from-DS", addr1=pkt.addr3, addr2=AP_MAC,addr3=AP_MAC) / Dot11QoS(A_MSDU_Present=1)
                #               / Dot11(addr1="50:e0:85:85:b4:b6", addr2="02:01:20:d0:3d:22") / lengthMSDU / LLC(dsap=0xaa,ssap=0xaa,ctrl=0x03) / org / packet_msdu1 / packet_msdu1)
                radioTap = b'\x00\x00\x52\x00\x2a\x40\xd0\xa8\x20\x08\x00\xa0\x20\x08\x00\xc0\x01\x00\x00\x00\x10\x00\xcc\x15\x40' \
                           b'\x01\xc0\x00\x00\x00\x00\x00\x2e\x6c\x0b\x00\x80\x00\x00\x00\xac\x2e\x00\xcd\x00\x00\x00\x00\x16\x00\x11' \
                           b'\x03\xfc\xc7\x7e\x00\x53\x24\x00\x00\x80\x20\x02\x7f\x02\x00\x40\x15\xc0\x00\xbd\x01\xf6\x54\x25\x01\x02\x00\x01\x00\x00\x00'

                ieee = b'\x88\x02\x30\x00\x50\xe0\x85\x85\xb4\xb6\x6c\xab\x05\x9e\x4b\x6e\x6c\xab\x05\x9e\x4b\x6e\x50\xf0\x80\x00'
                msu = b'\x50\xe0\x85\x85\xb4\xb6\x02\x10\x20\xd0\x3d\x22\x04\x0c\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x04\x04\xa3\x31\x40\x00\x44' \
                      b'\x11\x4b\xd9\xc0\xa8\x63\x1a\xc0\xa8\x63\x73\x14\x51\xce\xac\x03\xf0\x94\xbf\x00\x10'
                s = conf.L2socket('wlx00c0caa4737c')
                s.send(radioTap + ieee + msu)
                #packet.append(RadioTap() / Dot11(type=2, subtype=8, FCfield="from-DS", addr1=pkt.addr3, addr2=AP_MAC,addr3=AP_MAC) / Dot11QoS(A_MSDU_Present=1))
                #sendp(packet, iface=IFACE, verbose=False)
                print("Enviado paquete AMPDU")
                #Paquete Block ACK request
                packet = []
                data = "\x01\x00\x00\x00"
                packet.append(RadioTap() / Dot11(type=1, subtype=8, addr1=pkt.addr2, addr2=AP_MAC) / data)
                sendp(packet, iface=IFACE, verbose=False)
                print("Enviado correctamente Block ACK request")

    #Capturamos el Probe Request enviado por STA
    if pkt.haslayer(scapy.Dot11Elt) and pkt.type==0 and pkt.subtype == 4:
        infoProbRequest=pkt.getlayer(Dot11Elt)
        if pkt.subtype not in ap_list:
            if infoProbRequest.info.decode() == "ap0":
                ap_list.append(pkt.subtype)
                #Paquete Probe Response
                packet = []
                packet.append(
                    RadioTap() / Dot11(subtype=5, addr1=AP_MAC_2, addr2=AP_MAC,addr3=AP_MAC) / Dot11ProbeResp(cap="ESS+CFP") / Dot11Elt(ID='SSID',
                                                                                          info=infoProbRequest.info.decode()) /
                    Dot11Elt(ID='Supported Rates', info="\x82\x84\x8b\x0c\x12\x96\x18\x24") / Dot11Elt(ID='DSSS Set',info=chr(56)) /
                    Dot11EltHTCapabilities(SM_Power_Save=3, Short_GI_20Mhz=1, Tx_STBC=1, Rx_STBC=1, Max_A_MSDU=1,
                                           DSSS_CCK=1) /
                    Dot11Elt(ID='Extended Supported Rates', info="\xb0\x48\x60\x6c"))

                sendp(packet, iface=IFACE, verbose=False)
                print("Enviado correctamente Probe response..")



#SINCRONIZACION:
#Paquete BEACON :periódicamente desde un punto de acceso a anunciar su presencia y proporcionar el SSID, y otros parámetros para WNIC dentro del rango
#SSID = Service Set ID (AP’s nickname)
#Supported Rates (MegaBits/S)=  Velocidad de datos compatibles

packet = []
packet.append(RadioTap() / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=AP_MAC, addr3=AP_MAC)
              / Dot11Beacon(cap="ESS+CFP") / Dot11Elt(ID='SSID', info="ap0") / Dot11Elt(ID='Supported Rates',
                                                                                              info="\x0c\x12\x18\x24\x30\x48\x60\x6c") /
              Dot11Elt(ID='DSSS Set', info=chr(56)))


#Enviamos el Beacon
sendp(packet, iface=IFACE, verbose=False)
print("Beacon enviado")
scapy.sniff(iface=IFACE, prn=PacketHandler, timeout=30000)

