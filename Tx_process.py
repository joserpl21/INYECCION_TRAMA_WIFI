# -*- coding: utf-8 -*-
import sys
import scapy
from scapy.layers.dot11 import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp

from datos import *

ap_list = []  # Lista de indices para controlar que paquetes nos han llegado
IFACE = 'wlx00c0caa4737b'  # Interfaz de la targeta de red del transmisor
AP_MAC = '00:c0:ca:a4:73:7b'  # Direccion mac del transmisor
AP_MAC_2 = '00:c0:ca:a4:73:7c'  # Direccion mac del receptor()
rates = 0  # Velocidad de transmision
forma = 0

key = b'\x01\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a'
ps = [179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224139931,
    179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859,
    179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224138297,
    179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224139329,
    179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224140927]

xs = [51062515417529277526945128307594259195486583110720791748540527192733834855416286031598772289032860827130947052526578700038323006416125243222827197411066586011800102679460005522707833206714097782604925269619912549204174317400963779664751820664615965803468126412262664097293951929592234969612116409114015825578,
    48020969358492679318863735534997180836170863661985692071726993034945946832746279123965114000283661643882335792316790291443804567542156954397126787358641608186232956803797411368596530278760639421169306736267892649484550224775691166079443632627835531814801183167613013316799479791100311001779564647278762633541,
    127883885709200231651531696232276839856603698464079978162414254212552597368183998395595141173511918672840654695565973660314451967937317112761430727264115716645572906988214807983849346662331766753390640744157059955164510753085793695438864559716346726908438044825624280598567036601163766418531414128353078978638,
    60289359314090800190445649839761805182970713176385665388725978516802749898936200978117637449999387343946013900696217422976139698441294066585518338866803586379416850032284845930575174301972207267802422925588618636466646877561627583887286087568338746101684315058628918456593728486373451814620465060602382402468,
    146257116770323725965981324897286806168341858221148034876128508055102276499603303673631985324947439905458689639993428344141525575761914704312791227363983881912239665462812106881036926673016654640403838713144881828493708775552838727007407036048569996466164739591282939912499909155976806770375009287739246838950]

Hdr = 7015584123041823511118356678864494506768429930840562545412148912629539878530091445544494631192638152240459158965235731000721523670511550392942548294504219396133626645099589512357952193528605825058086441176243751682379295569249313773568751237886215641000467415006110244950130540312306619248720671236940046238679212810167963687550581330171336308448314363185605352228010853943136978888629243552551778193591255476672405341809430793385234125754836989144448914450601198758268864924477642352421976246125273639878000740300058462358751868730635682212696033092630859757874070738295951604848754707337975489220747048022945315863

def PacketHandler(pkt):
    # Capturamos el Assoc request
    if pkt.subtype == 0:
        if pkt.subtype not in ap_list:
            infoPacket = pkt.getlayer(Dot11Elt)
            if infoPacket.info.decode() == "ap0":
                ap_list.append(pkt.subtype)
                packet = []
                packet.append(
                    RadioTap(present='Rate', Rate=int(rates)) / Dot11(subtype=1, addr1=pkt.addr2, addr2=AP_MAC,
                                                                      addr3=AP_MAC) / Dot11AssoResp(cap="ESS+CFP") /
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
                packet.append(
                    RadioTap(present='Rate', Rate=int(rates)) / Dot11(subtype=13, addr1=pkt.addr2, addr2=AP_MAC,
                                                                      addr3=AP_MAC) / data / Dot11Elt(ID='SSID',
                                                                                                      info=infoPacket.info.decode()))
                sendp(packet, iface=IFACE, verbose=False)
                print("Enviado correctamente ADDBA Request..")

    # Capturamos el ADDBA Response
    if pkt.type == 0 and pkt.subtype == 13:
        if pkt.subtype not in ap_list:
            if pkt.addr2 == AP_MAC_2:
                ap_list.append(pkt.subtype)
                # Paquete AMPDU SIMPLE
                print("Forma seleccionada: ", forma)

                if int(forma) == 1:
                    AMPDU, AMPDUint = cifrarNORMAL(key)
                    packet = []
                    qoscontrol = b'\x00\x00'
                    packet.append(RadioTap() / Dot11(type=2, subtype=8, addr1=pkt.addr2, addr2=AP_MAC,
                                                     addr3=AP_MAC) / qoscontrol / AMPDU)
                    sendp(packet, iface=IFACE, verbose=False)
                if int(forma) == 2:
                    packet = []
                    qoscontrol = b'\x00\x00'
                    mpduCi_Hex, mpduCi = cifrarCRT(ps,xs,Hdr)
                    packet.append(RadioTap() / Dot11(type=2, subtype=8, addr1=pkt.addr2, addr2=AP_MAC, addr3=AP_MAC) / qoscontrol / mpduCi_Hex)
                    print("Paquete cifrado enviado")
                    print(hexdump(mpduCi_Hex))
                    sendp(packet, iface=IFACE, verbose=False)
                print("Enviado paquete AMPDU")
                # Paquete Block ACK request
                packet = []
                data = "\x01\x00\x00\x00"
                packet.append(RadioTap(present='Rate', Rate=int(rates)) / Dot11(type=1, subtype=8, addr1=pkt.addr2,
                                                                                addr2=AP_MAC) / data)
                sendp(packet, iface=IFACE, verbose=False)
                # s.close()
                print("Enviado correctamente Block ACK request")
                exit()

    # Capturamos el Probe Request enviado por STA
    if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 4:
        infoProbRequest = pkt.getlayer(Dot11Elt)
        if pkt.subtype not in ap_list:
            if infoProbRequest.info.decode() == "ap0":
                ap_list.append(pkt.subtype)
                # Paquete Probe Response
                packet = []
                packet.append(
                    RadioTap(present='Rate+A_MPDU', Rate=18, A_MPDU_flags='KnownEOF', A_MPDU_ref=1298623) / Dot11(
                        subtype=5, addr1=AP_MAC_2, addr2=AP_MAC, addr3=AP_MAC) / Dot11ProbeResp(
                        cap="ESS+CFP") / Dot11Elt(ID='SSID',
                                                  info=infoProbRequest.info.decode()) /
                    Dot11Elt(ID='Supported Rates', info="\x82\x84\x8b\x0c\x12\x96\x18\x24") / Dot11Elt(ID='DSSS Set',
                                                                                                       info=chr(56)) /
                    Dot11EltHTCapabilities(SM_Power_Save=3, Short_GI_20Mhz=1, Tx_STBC=1, Rx_STBC=1, Max_A_MSDU=1,
                                           DSSS_CCK=1) /
                    Dot11Elt(ID='Extended Supported Rates', info="\xb0\x48\x60\x6c"))

                sendp(packet, iface=IFACE, verbose=False)
                print("Enviado correctamente Probe response..")


# SINCRONIZACION:
# Paquete BEACON :periódicamente desde un punto de acceso a anunciar su presencia y proporcionar el SSID, y otros parámetros para WNIC dentro del rango
# SSID = Service Set ID (AP’s nickname)
# Supported Rates (MegaBits/S)=  Velocidad de datos compatibles
# DSSS Set informacion del canalr sobre el cual se esta transmitiendo
packet = []
packet.append(RadioTap() / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=AP_MAC, addr3=AP_MAC)
              / Dot11Beacon(cap="ESS+CFP") / Dot11Elt(ID='SSID', info="ap0") / Dot11Elt(ID='Supported Rates',
                                                                                        info="\x0c\x12\x18\x24\x30\x48\x60\x6c") /
              Dot11Elt(ID='DSSS Set', info=chr(56)))

# Enviamos el Beacon
sendp(packet, iface=IFACE, verbose=False)
# Almacenamos el valor de la velocidad de transmision que se ha elegido
rates = sys.argv[1]
forma = sys.argv[2]
print("Beacon enviado")
scapy.sniff(iface=IFACE, prn=PacketHandler, timeout=30000)
