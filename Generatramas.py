#2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
#import binascii
import zlib
import secrets
from scapy.utils import hexdump


def MSDU_gen (longitud_payload, no_ultimo):                                # Función para quenerar un MSDU de datos aleatorio, pero con cabeceras correctas
    DA = secrets.token_bytes(6)                                # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    SA = secrets.token_bytes(6)                                         # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Payload = secrets.token_bytes(longitud_payload)                          # Elegimos una carga aleatoria de tamaño fijado en la entrada
    Imponible =DA + SA + longitud_payload.to_bytes(2, byteorder='big') + Payload

    longitud_padding = 4 - (len(Imponible)%4)                             # Calculamos la longitud del padding

    if ((longitud_padding != 4) and (no_ultimo == 'true')):
        Mesh_flags = b'\x40'
        sec=secrets.token_bytes(longitud_padding)
        MSDU = Imponible + b'\x40'
        #print("Se ha agregado padding")
    else: MSDU = Imponible                                                 # Añadimos el padding si lo necesita
    #print("MSDU: ")
    #print(hexdump(MSDU))
    a=int.from_bytes(MSDU, byteorder='big')
    return a


def AMSDU_gen (longitud_agregado, longitud_payload):                      # Función para generar un AMSDU con una cantidad de MSDUs determinados
                                                                          # de longitud determinada
    AMSDU = 0                                                             # Inicializacion del AMSDU
    MSDUs = []
    filtro1 = (1 << 112)- 1                                               # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    for i in range (longitud_agregado - 1):                               # Lo construímos adjuntando cada MSDU
        MSDU = MSDU_gen(longitud_payload, 'true')
        bytes_resultantes = (7 + MSDU.bit_length()) // 8
        cabecera = (MSDU & (filtro1 << (8 * (bytes_resultantes - 14)))) >> (8 * (bytes_resultantes - 14))
                                                                          # Calculamos la cabecera
        longitud = cabecera & filtro2                                     # Y la longitud del MSDU
        pad = 4 - (longitud % 4)
        if pad == 4: pad = 0
        MSDUs.append(MSDU)
        AMSDU = (AMSDU << (8 * bytes_resultantes)) ^ MSDU
    MSDU = MSDU_gen(longitud_payload, 'false')                            # El ultimo MSDU sin padding
    MSDUs.append(MSDU)
    AMSDU = (AMSDU << (8 * ((7 + MSDU.bit_length()) // 8))) ^ MSDU
    return (AMSDU, MSDUs)

def MPDU_gen (MSDU,opc):                                                      # Función para generar un MPDFU a partir de un MSDU
    frame_control = b'\x20\xe5'                                           # version_del_protocolo = '00'. 2 bits con valor por defecto 0
                                                                          # tipo = '100000'. Trama de datos con subtipo a 0
                                                                          # to_DS = '1'.   Vamos a llenar
                                                                          # from_DS = '1'  todas las direcciones
                                                                          # more_fragments = '1'
                                                                          # retry = '0'
                                                                          # power_management = '0'
                                                                          # more_data = '1'
                                                                          # wep = '0'
                                                                          # order = '1' ordenados
                                                                          # frame_control = (version_del_protocolo + tipo + to_DS + from_DS + more_fragments
                                                                          # + retry + power_management +  more_data + wep + order)
    Duration = b'\x11\x00'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Address2 = b'\x00\xc0\xca\xa4\x73\x7b'  # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Address3 = b'\x00\xc0\xca\xa4\x73\x7b'
    if opc==1:
        Address1 = b'\x00\xc0\xca\xa4\x73\x7c'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio

    elif opc==2:
        Address1 = b'\x00\xc0\xca\xa8\x87\xa5'
    else:
        Address1 = secrets.token_bytes(6)  # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio

    Sequence_control = b'\x01\x00'                                        # Supondremos sin fragmentación del MSDU
    Address4 = b'\x01\xc0\xca\xa4\x73\x7b'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
                                                                          # No incluimos los byates de QoS y de control HT porque hemos considerado
                                                                          # que la trama va a ser de datos.
    Imponible = (frame_control + Duration + Address1 + Address2 + Address3 + Sequence_control
               + Address4 + MSDU.to_bytes((MSDU.bit_length() + 7) // 8, byteorder='big'))
    FCS = zlib.crc32(Imponible)
    MPDU = Imponible + FCS.to_bytes(4, byteorder='big')                   # Adjuntamos el CRC
    print("MPDU: ")
    print(hexdump(MPDU))
    return int.from_bytes(MPDU, byteorder='big')

def crc8(data):                                                           # Función para calcular el CRC8 de las cabececeras
    n = data.bit_length()
    divisor = 263 << (n - 9)
    tope = (1 << (n-1)) - 1
    for i in range(n, 8, -1):
          if data >= tope: data = data ^ divisor
          divisor = divisor >> 1
          tope = tope >> 1
    return data
