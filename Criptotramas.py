# 2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
from Generatramas import *
import secrets
from datetime import datetime, timedelta
from Crypto.Cipher import  AES

import functools
import zlib

def  MPDU_dec(MPDU,key):  # Fucnión para generar un MPDU cifrado
    PN = int.from_bytes(secrets.token_bytes(6),byteorder='big')  # Contador de AMPDUs cifradas que debería sincronizarser con el cliente
    PN = PN + 1
    if (PN == (1 << 48)): PN = 0
    bytes_MPDU = (7 + MPDU.bit_length()) // 8
    old_header = MPDU >> (8 * (bytes_MPDU - 30))  # Separo la antigua cabecera de 30 bytes
    payload = (MPDU ^ (old_header << (8 * (bytes_MPDU - 30)))) >> 32
    aux = old_header
    Address4 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 48
    Sequence_control = aux & ((1 << 16) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 16
    Address3 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 48
    Address2 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 48
    Address1 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 64
    frame_control = aux & ((1 << 16) - 1)  # Copiamos el valor de este campo de la trama entrante
    AAD = (((((((((((frame_control << 48) ^ Address1) << 48) ^ Address2) << 48)
                ^ Address3) << 16) ^ Sequence_control) << 48) ^ Address4))
    # AAD = frame_control + Address1 + Address2 + Address3 + Sequence_control + Address4
    Nonce = (Address2 << 48) ^ PN  # Debería tener 13 octetos, pero el primero es \x00
    cipher = AES.new(key, AES.MODE_GCM, nonce=Nonce.to_bytes(13, byteorder='big'), mac_len=8)
    # Definimos el modo de cifrado AES-GCM
    cipher.update(AAD.to_bytes(28, byteorder='big'))  # Testigo de autenticación
    ciphertext, mic = cipher.encrypt_and_digest(payload.to_bytes(bytes_MPDU - 34, byteorder='big'))
    # Ciframos y a continuación definimos la cabecera de cifrado que heredamos
    # del sistema CCM que suponemos igual al del GCM
    aux = (1 << 8) - 1
    PN0 = PN & aux
    aux = aux << 8
    PN1 = (PN & aux) >> 8
    aux = aux << 8
    PN2 = (PN & aux) >> 16
    aux = aux << 8
    PN3 = (PN & aux) >> 24
    aux = aux << 8
    PN4 = (PN & aux) >> 32
    aux = aux << 8
    PN5 = (PN & aux) >> 40
    ccmp_header = ((((((((((((PN0 << 8) ^ PN1) << 16)
                           ^ 4) << 8) ^ PN2) << 8) ^ PN3) << 8) ^ PN4) << 8) ^ PN5).to_bytes(8,
                                                                                             byteorder='big')  # Hemos fijado el Key_ID=00
    Imponible = (old_header.to_bytes(30, byteorder='big')
                 + ccmp_header + ciphertext + mic)  # Lo unimos todo para calcula el CRC
    FCS = zlib.crc32(Imponible)  # Calculamos el CRC
    MPDU_enc = Imponible + FCS.to_bytes(4, byteorder='big')  # Lo unimos todo para generar el nuevo MPDU cifrado
    return (int.from_bytes(MPDU_enc, byteorder='big'))  # Además enviamos la clave para la emulación

def AMPDU_enc2(f,key):  # Función para generar un AMPDU con MSDUs aleatorios
    tope_t = timedelta(microseconds=20000)  # Tope temporal
    tope_m = 7965  # Tope AMPDU (7965)
    tope_d = 2304  # Tope AMSDU (2304)
    AMPDUs = []  # Inicializacion de los AMSDUs
    lapsos = []
    lanzamientos = []  # Inicializacion del almacen de instantes de transmision
    agregados = []  # Inicializacion del almacen con la cantidad de MPDUs que hay en cada AMPDU
    claves = []  # Inicializacion del almacen de almacenes de claves para cada AMPDU
    tx = timedelta(0)  # Tiempo de transmisión acumulado
    ultimo = 'false'  # Booleano que controla si he llegado al ultimo MPDU del AMPDU
    final = 'false'  # Booleano que controla si he llegado al final del fichero
    i = 0  # Contador de MPDUs almacenados
    retraso = timedelta(0)  # Tiempo de espera que ha pasado desde la llegada del ultimo paquete que ha sido
    # transmitido
    longitudes_AMPDU = []  # Inicializamos longitudes del AMPDU
    AMPDU_acumulado_l = 0  # Inicializamos la longitud acumulada del AMPDU
    AMPDU_acumulado_t = timedelta(0)  # Inicializamos el tiempo de retardo para la creacion del AMPDU
    while (final == 'false'):  # Parar si hemos llegado al final del fichero
        while (ultimo == 'false'):  # Parar si hemos llegado al final del AMPDU
            lectura = f.readline()  # Leo la presunta longitud del MSDU
            if (lectura == ''):
                final = 'true'
                ultimo = 'true'
            else:
                longitud_nuevo = int(lectura)  # Leo la longitud del candidato
                tiempo_nuevo = timedelta(microseconds=int(lectura))  # y el tiempo de llegada desde la anterior
                if (tiempo_nuevo > retraso):
                    paso = tiempo_nuevo - retraso
                else:
                    paso = tiempo_nuevo
                if (((AMPDU_acumulado_l + longitud_nuevo) > tope_d) or ((AMPDU_acumulado_t + paso) > tope_t)):
                    ultimo = 'true'
                else:
                    if retraso > tiempo_nuevo:  # Quitamos del retraso el tiempo de retardo
                        retraso = retraso - tiempo_nuevo
                        tiempo_nuevo = timedelta(0)
                    else:  # o viceversa
                        tiempo_nuevo = tiempo_nuevo - retraso
                        retraso = timedelta(0)
                    AMPDU_acumulado_l += longitud_nuevo
                    AMPDU_acumulado_t += tiempo_nuevo
                    longitudes_AMPDU.append(longitud_nuevo)
                    i += 1

        AMPDU = 0  # Inicializamos el AMPDU
        #clave = []  # Inicializamos la lista de claves de cada AMPDU
        for j in range(i - 1):
            MSDU = MSDU_gen(longitudes_AMPDU[j], 'true')  # Construímos cada uno de los MSDU's que componenen la MPDU,
            MPDU = MPDU_gen(MSDU)
            print("MPDU")
            hexMPDU = MPDU.to_bytes((MPDU.bit_length() + 7) // 8, byteorder='big')
            print(hexdump(hexMPDU))
            MPDU_encrypted = MPDU_enc(MPDU,key)  # Para cada MPDU construimos su correspondiente cifrado
            longitudes = (7 + MPDU_encrypted.bit_length()) // 8
            #clave.append(MPDU_encrypted[1])  # Y posteriomente lo ciframos
            # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
            # y luego lo unimos todo
            Delimiter = (15 << 12) ^ longitudes
            FCS = crc8(Delimiter)
            Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
            AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitudes)) ^ MPDU_encrypted
            longitud_padding = 4 - (longitudes % 4)  # Calculamos la longitud del padding
            if longitud_padding != 4: AMPDU = ((AMPDU << (8 * longitud_padding))
                                               ^ int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big'))
        MSDU = MSDU_gen(longitudes_AMPDU[i - 1], 'true')  # Construímos cada uno de los MSDU's que componenen la MPDU,
        MPDU = MPDU_gen(MSDU,0)
        print("MPDU")
        hexMPDU=MPDU.to_bytes((MPDU.bit_length() + 7) // 8, byteorder='big')
        print(hexdump(hexMPDU))
        MPDU_encrypted = MPDU_enc(MPDU,key)  # Para cada MPDU construimos su correspondiente cifrado
        longitudes = (7 + MPDU_encrypted.bit_length()) // 8
        #clave.append(MPDU_encrypted[1])  # Y posteriomente lo ciframos
        # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
        # y luego lo unimos todo
        Delimiter = (15 << 12) ^ longitudes
        FCS = crc8(Delimiter)
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitudes)) ^ MPDU_encrypted
        AMPDUs.append(AMPDU)  # Almacenamos el AMPDU
        #claves.append(clave)


    return AMPDUs


def AMPDU_dec(AMPDU, claves):  # Función para descifrar un AMPDU cifrado con las claves
    MSDUs = []  # Inicializacion de una lista de MPDUs y MSDUs
    i = 0  # Contador de MPDUs
    filtro1 = ((1 << 32) - 1)  # Filtros para separar campos
    filtro2 = ((1 << 12) - 1) << 16
    tiempo_inicial = datetime.now()
    while (AMPDU != 0):  # Vamos a recorrer el AMPDU hasta que se vacíe
        bytes_restantes = (7 + AMPDU.bit_length()) // 8
        Delimiter = (AMPDU & (filtro1 << (8 * (bytes_restantes - 4)))) >> (8 * (bytes_restantes - 4))
        # Separamos el delimitador
        longitud = (Delimiter & filtro2) >> 16  # Construímos cada uno de los MPDU's que componen la AMPDU
        pad = 4 - (longitud % 4)  # Separamos el Padding
        if ((pad == 4) or ((longitud + pad) > (bytes_restantes - 4))): pad = 0
        filtro = ((1 << 8 * (longitud + pad)) - 1) << (8 * (bytes_restantes - (4 + longitud + pad)))
        MPDU_encrypted = (AMPDU & filtro) >> (8 * (bytes_restantes - (4 + longitud + pad)))
        AMPDU = (AMPDU ^ (((Delimiter << (8 * (longitud + pad)))
                           ^ MPDU_encrypted) << (8 * (bytes_restantes - (4 + longitud + pad)))))
        MPDU_encrypted = MPDU_encrypted >> (8 * pad)  # Ya he separado el AMPDU cifrado
        MSDU = MPDU_dec(MPDU_encrypted, claves)  # Y por último descifro el MPDU
        MSDUs.append(MSDU)
        i = i + 1
    lapso = datetime.now() - tiempo_inicial
    return MSDUs, lapso  # Devuelvo dos listas con todos los MPDUs y MSDUs descifrados

def MPDU_enc(MPDU,key):  # Fucnión para generar un MPDU cifrado
    PN = int.from_bytes(secrets.token_bytes(6),byteorder='big')  # Contador de AMPDUs cifradas que debería sincronizarser con el cliente
    PN = PN + 1
    if (PN == (1 << 48)): PN = 0
    bytes_MPDU = (7 + MPDU.bit_length()) // 8
    old_header = MPDU >> (8 * (bytes_MPDU - 30))  # Separo la antigua cabecera de 30 bytes
    payload = (MPDU ^ (old_header << (8 * (bytes_MPDU - 30)))) >> 32
    aux = old_header
    Address4 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 48
    Sequence_control = aux & ((1 << 16) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 16
    Address3 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 48
    Address2 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 48
    Address1 = aux & ((1 << 48) - 1)  # Copiamos el valor de este campo de la trama entrante
    aux = aux >> 64
    frame_control = aux & ((1 << 16) - 1)  # Copiamos el valor de este campo de la trama entrante
    AAD = (((((((((((frame_control << 48) ^ Address1) << 48) ^ Address2) << 48)
                ^ Address3) << 16) ^ Sequence_control) << 48) ^ Address4))
    # AAD = frame_control + Address1 + Address2 + Address3 + Sequence_control + Address4
    Nonce = (Address2 << 48) ^ PN  # Debería tener 13 octetos, pero el primero es \x00
    cipher = AES.new(key, AES.MODE_GCM, nonce=Nonce.to_bytes(13, byteorder='big'), mac_len=8)
    # Definimos el modo de cifrado AES-GCM
    cipher.update(AAD.to_bytes(28, byteorder='big'))  # Testigo de autenticación
    ciphertext, mic = cipher.encrypt_and_digest(payload.to_bytes(bytes_MPDU - 34, byteorder='big'))
    # Ciframos y a continuación definimos la cabecera de cifrado que heredamos
    # del sistema CCM que suponemos igual al del GCM
    aux = (1 << 8) - 1
    PN0 = PN & aux
    aux = aux << 8
    PN1 = (PN & aux) >> 8
    aux = aux << 8
    PN2 = (PN & aux) >> 16
    aux = aux << 8
    PN3 = (PN & aux) >> 24
    aux = aux << 8
    PN4 = (PN & aux) >> 32
    aux = aux << 8
    PN5 = (PN & aux) >> 40
    ccmp_header = ((((((((((((PN0 << 8) ^ PN1) << 16)
                           ^ 4) << 8) ^ PN2) << 8) ^ PN3) << 8) ^ PN4) << 8) ^ PN5).to_bytes(8,
                                                                                             byteorder='big')  # Hemos fijado el Key_ID=00
    Imponible = (old_header.to_bytes(30, byteorder='big')
                 + ccmp_header + ciphertext + mic)  # Lo unimos todo para calcula el CRC
    FCS = zlib.crc32(Imponible)  # Calculamos el CRC
    MPDU_enc = Imponible + FCS.to_bytes(4, byteorder='big')  # Lo unimos todo para generar el nuevo MPDU cifrado
    return (int.from_bytes(MPDU_enc, byteorder='big'))  # Además enviamos la clave para la emulación


def AMSDU_enc(MSDU,ps,xs,Hdr):  # Función que cifra un AMSDU con el teorema chino del resto (CRT) - modificacion con poner un AMPDU
    a = []  # Máscaras aleatorias
    n = 0  # Contador de MSDUs
    for i in MSDU:
        a.append((i + pow(Hdr, xs[n], ps[n])) % ps[n])  # y enmascaro el MSDU
        n = n + 1
    return chinese_remainder(ps, a)  # Devuelvo la cabecera aleatoria y un MPDU cifrado con el CRT


def AMSDU_dec(Hdr, MPDU, ps, xs):  # Función para descifrar un MPDU que contine una MSDU cifrado con CRT
    MSDUs = []  # Inicializamos la lista de salida
    for i in range(len(ps)):
        MSDUs.append((MPDU - pow(Hdr, xs[i], ps[i])) % ps[i])
    return (MSDUs)


def chinese_remainder(n, a):  # Función para calcular el cifrado con el CRT
    sum = 0
    prod = functools.reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod


def mul_inv(a, b):  # Función para calcular el inverso multiplicativo modular
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        #print("b ? ",b)
        #print("a ? ", a)
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

