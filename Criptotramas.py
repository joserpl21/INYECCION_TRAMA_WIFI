# 2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
from Generatramas import *
import secrets
import random
from datetime import datetime, timedelta
from random import getrandbits
from Crypto.Cipher import  AES
#import sympy
#from sympy.ntheory import nextprime, is_quad_residue, isprime
import functools
#pip3 install pycryptodome
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
    FCS = binascii.crc32(Imponible)  # Calculamos el CRC
    MPDU_enc = Imponible + FCS.to_bytes(4, byteorder='big')  # Lo unimos todo para generar el nuevo MPDU cifrado
    return (int.from_bytes(MPDU_enc, byteorder='big'))  # Además enviamos la clave para la emulación


def MPDU_dec(MPDU, key):  # Función para descifrar el AMPDU cifrado
    bytes_MPDU = (7 + MPDU.bit_length()) // 8
    header = MPDU >> 8 * (bytes_MPDU - 38)  # Separo las cabeceras del MPDU cifrado
    payload = MPDU ^ (header << (8 * (bytes_MPDU - 38)))
    aux = (1 << 8) - 1
    PN = header & aux  # PN5
    header = header >> 8
    PN = (PN << 8) ^ (header & aux)  # PN4
    header = header >> 8
    PN = (PN << 8) ^ (header & aux)  # PN3
    header = header >> 8
    PN = (PN << 8) ^ (header & aux)  # PN2
    header = header >> 24
    PN = (PN << 8) ^ (header & aux)  # PN1
    header = header >> 8
    PN = (PN << 8) ^ (header & aux)  # PN0
    header = header >> 8
    aux = header
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
    payload = payload >> 32  # Eliminamos el FCS
    mic = payload & ((1 << 64) - 1)  # Extraemos mic
    payload = payload >> 64  # y lo eliminamos del payload
    try:  # Procedemos a descifrar, definiciendo los parametros y devolviendo el texto plano
        cipher = AES.new(key, AES.MODE_GCM, nonce=Nonce.to_bytes(13, byteorder='big'), mac_len=8)
        cipher.update(AAD.to_bytes(28, byteorder='big'))
        plaintext = cipher.decrypt_and_verify(payload.to_bytes(bytes_MPDU - 50,
                                                               byteorder='big'), mic.to_bytes(8, byteorder='big'))
    except (ValueError, KeyError):
        print("Incorrecto")
    return int.from_bytes(plaintext, byteorder='big')  # Devolvemos el texto plano


def AMPDU_enc(longitud_agregado, longitud_payload):  # Función para construir un AMPDU cifrado
    AMPDU = 0  # Inicializacion del AMPDU
    claves = []  # Inicialización de una lista de claves que necesitaremos para descifrar
    for i in range(longitud_agregado - 1):  # Construimos agregando los MPDUs
        MSDU = MSDU_gen(longitud_payload, 'false')  # Construímos cada uno de los MSDU's que componen la MPDU
        MPDU = MPDU_gen(MSDU)
        MPDU_encrypted = MPDU_enc(MPDU)  # Para cada MSDU construimos su correspondiente AMPDU
        longitud = (7 + MPDU_encrypted[0].bit_length()) // 8
        claves.append(MPDU_encrypted[1])  # Y posteriomente lo ciframos
        # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
        # y luego lo unimos todo
        Delimiter = (15 << 12) ^ longitud
        FCS = crc8(Delimiter)
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitud)) ^ MPDU_encrypted[0]
        longitud_padding = 4 - (longitud % 4)  # Calculamos la longitud del padding
        if longitud_padding != 4: AMPDU = ((AMPDU << (8 * longitud_padding))
                                           ^ int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big'))
    MSDU = MSDU_gen(longitud_payload, 'false')  # Añadimos el último sin padding
    MPDU = MPDU_gen(MSDU)
    MPDU_encrypted = MPDU_enc(MPDU)
    longitud = (7 + MPDU_encrypted[0].bit_length()) // 8
    claves.append(MPDU_encrypted[1])
    Delimiter = (15 << 12) ^ longitud
    FCS = crc8(Delimiter)
    Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
    AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitud)) ^ MPDU_encrypted[0]
    return (AMPDU, claves)  # Devolvemos la AMPDU cifrada y las claves


def AMSDU_to_AMPDU_enc(AMSDU):  # Función para construir un AMPDU cifrado a partir de un AMSDU
    AMPDU = 0  # Inicializacion del AMPDU
    claves = []  # Inicialización de una lista de claves que necesitaremos para descifrar
    filtro1 = (1 << 112) - 1  # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    while (AMSDU != 0):  # Vamos a recorrer el AMSDU hasta que se vacíe
        bytes_restantes = (7 + AMSDU.bit_length()) // 8
        cabecera = (AMSDU & (filtro1 << (8 * (bytes_restantes - 14)))) >> (8 * (bytes_restantes - 14))
        # Calculamos la cabecera
        longitud_plain = cabecera & filtro2  # Y la longitud del MSDU
        pad = 4 - (longitud_plain % 4)
        if ((pad == 4) or (longitud_plain >= (bytes_restantes - 32))): pad = 0
        # Determinamos si el MSDU contiene padding
        filtro = ((1 << (8 * (14 + 18 + longitud_plain + pad))) - 1) << (
                    8 * (bytes_restantes - (14 + 18 + longitud_plain + pad)))
        # He sumado 18 bytes del Mesh Control
        MSDU_aux = (AMSDU & filtro) >> (8 * (bytes_restantes - (14 + 18 + longitud_plain + pad)))
        # Calculo el MSDU y lo quito del agregado
        AMSDU = AMSDU ^ (MSDU_aux << (8 * (bytes_restantes - (14 + 18 + longitud_plain + pad))))
        MPDU = MPDU_gen(MSDU_aux >> (8 * pad))  # Para cada MSDU construimos su correspondiente AMPDU
        MPDU_encrypted = MPDU_enc(MPDU)  # Para cada MSDU construimos su correspondiente AMPDU
        longitud = (7 + MPDU_encrypted[0].bit_length()) // 8
        claves.append(MPDU_encrypted[1])  # Y posteriomente lo ciframos
        # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
        # y luego lo unimos todo
        Delimiter = (15 << 12) ^ longitud
        FCS = crc8(Delimiter)
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitud)) ^ MPDU_encrypted[0]
        longitud_padding = 4 - (longitud % 4)  # Calculamos la longitud del padding
        if ((longitud_padding != 4) and (longitud_plain < (bytes_restantes - 4))):
            AMPDU = ((AMPDU << (8 * longitud_padding)) ^ (
                int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big')))
    return (AMPDU, claves)  # Devolvemos la AMPDU cifrada y las claves


def AMPDU_enc2(f, velocidad, slot_time, SIFS, preambulo, ack, CW,key):  # Función para generar un AMPDU con MSDUs aleatorios
    DIFS = 2 * slot_time + SIFS
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
            MPDU_encrypted = MPDU_enc(MPDU,key)  # Para cada MPDU construimos su correspondiente cifrado
            longitudes = (7 + MPDU_encrypted[0].bit_length()) // 8
            #clave.append(MPDU_encrypted[1])  # Y posteriomente lo ciframos
            # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
            # y luego lo unimos todo
            Delimiter = (15 << 12) ^ longitudes
            FCS = crc8(Delimiter)
            Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
            AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitudes)) ^ MPDU_encrypted[0]
            longitud_padding = 4 - (longitudes % 4)  # Calculamos la longitud del padding
            if longitud_padding != 4: AMPDU = ((AMPDU << (8 * longitud_padding))
                                               ^ int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big'))
        MSDU = MSDU_gen(longitudes_AMPDU[i - 1], 'true')  # Construímos cada uno de los MSDU's que componenen la MPDU,
        MPDU = MPDU_gen(MSDU)
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


def gen_retardoss_c(f, velocidad, slot_time, SIFS, preambulo, ack, CW,
                    k):  # Funcion para calcular los retardos de AMPDUs cifrados
    DIFS = 2 * slot_time + SIFS
    tope_t = timedelta(microseconds=20000)  # Tope temporal
    tope_m = 7965  # Tope AMPDU (7965)
    tope_d = 2304  # Tope AMSDU (2304)
    AMPDUs = []  # Inicializacion de los AMPDUs
    agregados = []  # Inicializacion del almacen con la cantidad de MPDUs que hay en cada AMPDU
    claves = []  # Inicializacion del almacen de almacenes de claves para cada AMPDU
    lanzamientos = []  # Tiempo en microsegundos entre los finales de las transmisiones de dos AMSDUs
    tx = timedelta(0)  # Tiempo de transmisión acumulado para AMSDUs
    filtro1 = (1 << 112) - 1  # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    retraso = timedelta(0)  # Tiempo de espera que ha pasado desde la llegada del ultimos paquetes que han
    AMPDU_acumulado_t = timedelta(0)  # Inicializamos el tiempo de retardo para la creacion del AMPDU
    lectura = f.readline()
    print(k)
    if (lectura == ''):
        final = 'true'
    else:
        final = 'false'
    while (final == 'false'):  # Parar si hemos llegado al final del fichero
        AMPDU = 0  # Inicializamos el AMPDU
        clave = []  # Inicializamos la lista de claves de cada AMPDU
        for j in range(k - 1):
            MSDU = MSDU_gen(int(lectura), 'true')  # Construímos cada uno de los MSDU's que componenen la MPDU,
            tiempo_nuevo = timedelta(microseconds=int(f.readline()))  # y el tiempo de llegada desde la anterior
            if retraso > tiempo_nuevo:  # Quitamos del retraso el tiempo de retardo
                retraso = retraso - tiempo_nuevo
                tiempo_nuevo = timedelta(0)
            else:  # o viceversa
                tiempo_nuevo = tiempo_nuevo - retraso
                retraso = timedelta(0)
            AMPDU_acumulado_t += tiempo_nuevo
            lectura = f.readline()
            MPDU = MPDU_gen(MSDU)
            MPDU_encrypted = MPDU_enc(MPDU)  # Para cada MPDU construimos su correspondiente cifrado
            longitudes = (7 + MPDU_encrypted[0].bit_length()) // 8
            clave.append(MPDU_encrypted[1])
            Delimiter = (
                                    15 << 12) ^ longitudes  # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
            FCS = crc8(Delimiter)  # y luego lo unimos todo
            Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
            AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitudes)) ^ MPDU_encrypted[0]
            longitud_padding = 4 - (longitudes % 4)  # Calculamos la longitud del padding
            if longitud_padding != 4: AMPDU = ((AMPDU << (8 * longitud_padding))
                                               ^ int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big'))
        MSDU = MSDU_gen(int(lectura), 'true')  # Construímos cada uno de los MSDU's que componenen la MPDU,
        tiempo_nuevo = timedelta(microseconds=int(f.readline()))
        if retraso > tiempo_nuevo:  # Quitamos del retraso el tiempo de retardo
            retraso = retraso - tiempo_nuevo
            tiempo_nuevo = timedelta(0)
        else:  # o viceversa
            tiempo_nuevo = tiempo_nuevo - retraso
            retraso = timedelta(0)
        AMPDU_acumulado_t += tiempo_nuevo
        MPDU = MPDU_gen(MSDU)
        MPDU_encrypted = MPDU_enc(MPDU)  # Para cada MPDU construimos su correspondiente cifrado
        longitudes = (7 + MPDU_encrypted[0].bit_length()) // 8
        clave.append(MPDU_encrypted[1])  # Y posteriomente lo ciframos
        Delimiter = (15 << 12) ^ longitudes  # Calculamos el correspondiente delimitador, fijando los bits resrvados a 1
        FCS = crc8(Delimiter)  # y luego lo unimos todo
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = (((AMPDU << 32) ^ Delimiter) << (8 * longitudes)) ^ MPDU_encrypted[0]
        AMPDUs.append(AMPDU)  # Almacenamos el AMPDU
        transmision = (round((AMPDU.bit_length() / velocidad)) + 2 * preambulo + ack + SIFS
                       + DIFS + (int.from_bytes(secrets.token_bytes(2), byteorder='big') >> (16 - CW)) * slot_time)
        #        transmision = (round((AMPDU.bit_length() + 48 * 8) * (10 ** 6)/(velocidad << 20)) + 4 * preambulo + 3 * SIFS
        #                     + DIFS + (1 << CW) * slot_time)                       Calculamos el tiempo de transmision del AMPDU
        tx += timedelta(microseconds=transmision)  # Lo acumulamos
        lectura = f.readline()
        if (lectura == ''): final = 'true'
        lanzamiento = AMPDU_acumulado_t
        lanzamiento += timedelta(
            microseconds=transmision)  # Calculamos el instante de transmisión tomando como referencia al anterior
        retraso += timedelta(microseconds=transmision)
        lanzamientos.append(lanzamiento)
        AMPDU_acumulado_t = timedelta(0)
        claves.append(clave)
    return (AMPDUs, claves, lanzamientos, tx)


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


def AMSDU_enc(AMSDU,MSDU):  # Función que cifra un AMSDU con el teorema chino del resto (CRT) - modificacion con poner un AMPDU
    MSDUs = []  # Creamos una lista para los MSDUs "desentramados"
    ps = [1100645304239144332874899719259313845702512851699,1100645304239144332874899719259330726252929972829,18465764008605840127818093568353291822549225699331595729]  # Claves p
    xs = [469185440907188674086266365887713402920751416175,469185440907188674086266365887713402920751416175,7016009363412435780763082007262025939147461935248010908]  # Claves x
    a = []  # Máscaras aleatorias
    n = 0  # Contador de MSDUs
    #Hdr = random.getrandbits(1023)  # Cabecera común para el cifrado aleatorio
    Hdr=15954397600484676080445144553223529992678013943537230069224121000855699303061777531981089406222510881421088752704688036147253082732657897862191895053631674856772128322391273493214154863018969779796561231280601263793302777253129776032382760813815413222441888256216530367314241202928278526289479100743111536202
    #print("HDR", Hdr)
    filtro1 = (1 << 112) - 1  # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    tiempo_inicial = datetime.now()
    for i in MSDU:
        print("MSDU ANTES DE ENCRIPTAR",i)
        #p = nextprime(i + 3)  # Calculo la clave p
        #ps.append(p)  # y la almaceno en una lista
        #xs.append(getrandbits(p.bit_length() - 1))  # Calculo la máscara aleatoria de cada diferente difrado
        a.append((i + pow(Hdr, xs[n], ps[n])) % ps[n])  # y enmascaro el MSDU
        n = n + 1

    return (Hdr, MPDU_gen(MSDU_gen2(chinese_remainder(ps, a))), ps, xs)  # Devuelvo la cabecera aleatoria y un MPDU cifrado con el CRT


"""        
    while (AMSDU != 0):  # Vamos a recorrer el AMSDU hasta que se vacíe
        bytes_restantes = (7 + AMSDU.bit_length()) // 8
        cabecera = (AMSDU & (filtro1 << (8 * (bytes_restantes - 14)))) >> (8 * (bytes_restantes - 14))
        # Calculamos la cabecera
        print("campo cabecera",bytes_restantes)
        longitud = cabecera & filtro2  # Y la longitud del MSDU
        print("campo longitud",longitud)
        #Hemos cambiado el valor de la longitud 100 = longitud_payload
        #longitud = 100  # Y la longitud del MSDU
        pad = 4 - (longitud % 4)
        if ((pad == 4) or ((8 * longitud) >= (AMSDU.bit_length() - 256))): pad = 0
        # Determinamos si el MSDU contiene padding
        print(bytes_restantes - (14 + 18 + longitud + pad))<< (8 * (bytes_restantes - (14 + 18 + longitud + pad)))
        filtro = ((1 << 8 * (14 + 18 + longitud + pad)) - 1)
        # He sumado 18 bytes del Mesh Control
        MSDU_aux = (AMSDU & filtro) >> (8 * (bytes_restantes - (14 + 18 + longitud + pad)))
        # Calculo el MSDU y lo quito del agregado
        AMSDU = AMSDU ^ ((MSDU_aux) << (8 * (bytes_restantes - (14 + 18 + longitud + pad))))
        MSDUs.append(MSDU_aux >> (8 * pad))
        p = nextprime(MSDUs[i] + 3)  # Calculo la clave p
        ps.append(p)  # y la almaceno en una lista
        xs.append(getrandbits(p.bit_length() - 1))  # Calculo la máscara aleatoria de cada diferente difrado
        a.append((MSDUs[i] + pow(Hdr, xs[i], p)) % p)  # y enmascaro el MSDU
        i = i + 1
    lapso = datetime.now() - tiempo_inicial
"""


def AMSDU_enc2(f, velocidad, slot_time, SIFS, preambulo, ack, CW, AMSDUs, m):
    DIFS = 2 * slot_time + SIFS
    Hdrs = []  # Inicializamos el almacen de cabeceras de los AMSDUs
    MPDUs = []
    ps = []
    xs = []
    lanzamientos = []
    #    m = open('Longitud_AMSDUs.DAT',"rb")
    retraso = timedelta(0)  # Inicializo retraso
    tx = timedelta(0)  # Inicializo el tiempo de transmision acumulado
    delta_time = timedelta(0)  # Inicializo el retardo
    #    longitud = pickle.load(m)
    #    print(longitud)
    i = 0  # Contador de los AMSDUs
    for AMSDU in AMSDUs:  # Recorro el almacen de longitudes de los AMSDUs
        tiempo_inicial = datetime.now()
        Hdr = getrandbits(1023)  # Cabecera común para el cifrado aleatorio
        Hdrs.append(Hdr)  # La almaceno
        #        print(longitud[iii])
        for ii in range(m):  # Recorro los MSDUs de cada AMSDU para calcular los intervalos de retardo entre cada AMSDU
            x = f.readline()
            y = f.readline()
            delta_time += timedelta(microseconds=int(y))
            #            largo = MSDUs[i].bit_length() + 1             # Calculo la longitud de la clave p
            i += 1  # Incremento el contador
        inter = MPDU_gen(MSDU_gen2((AMSDU << Hdr.bit_length()) ^ Hdr))
        # Agrego la cabecera al AMPDU
        MPDUs.append(inter)  # Almaceno el MPDU
        if retraso > delta_time:  # Actualizo retardos y retrasos
            retraso = retraso - delta_time
            delta_time = timedelta(0)
        else:
            delta_time = delta_time - retraso
            retraso = timedelta(0)
        transmision = (round((inter.bit_length() / velocidad)) + 2 * preambulo + ack + SIFS
                       + DIFS + (int.from_bytes(secrets.token_bytes(2), byteorder='big') >> (16 - CW)) * slot_time)
        #        transmision = (round((inter.bit_length() + 48 * 8) * (10 ** 6)/(velocidad << 20)) + 4 * preambulo + 3 * SIFS
        #                     + DIFS + (1 << CW) * slot_time)
        # Calculo el tiempo de transmision
        tx += timedelta(microseconds=transmision)  # Lo acumulo
        retraso += timedelta(microseconds=transmision)  # Acumulo la transmision al retraso
        #        lanzamiento = delta_time + lapso
        lanzamiento = delta_time + timedelta(microseconds=transmision)
        # Calculo el instante de transmision
        delta_time = timedelta(0)  # Inicializo de nuevo el retardo
        #        retraso += lapso
        lanzamientos.append(lanzamiento)  # Almaceno el instante de transmision
    #    print(Hdrs, MPDUs)
    return (Hdrs, MPDUs, lanzamientos, tx)


def AMSDU_dec(Hdr, MPDU, ps, xs):  # Función para descifrar un MPDU que contine una MSDU cifrado con CRT
    MSDUs = []  # Inicializamos la lista de salida
    longitud = (7 + MPDU.bit_length()) // 8  # Calculo la longitud en bytes del MPDU
    filtro = ((1 << (8 * (longitud - 34))) - 1) << 32  # Filtro para extraer el MPDU cifrado
    AMSDU = (MPDU & filtro) >> 32  # Extraído
    longitud = (7 + AMSDU.bit_length()) // 8
    filtro = (1 << (8 * (longitud - 32))) - 1  # Filtro para extraer el MSDU cifrado
    MSDU = AMSDU & filtro  # Extraído
    tiempo_inicial = datetime.now()
    for i in range(len(ps)):
        MSDUs.append((MSDU - pow(Hdr, xs[i], ps[i])) % ps[i])

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
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1


def demo():  # Funciones demo inciales para comprobar el buen funcionamiento de los programas
    print("Vamos a presentar la diferencia de longitud en los cifrados de tramas agregadas.")
    print("Hemos codificado las tramas como enteros por manejabilidad.")
    print("Pero se aprecia la diferencia de longitud")
    t = int(input("Introduce la cantidad de tramas que quieres agregar "))
    l = int(input("Introduce la cantidad de bytes que el payload que va a llevar en cada trama "))
    AMSDU, MSDUs = AMSDU_gen(t, l)
    print("MSDUs")
    print(MSDUs)
    print("AMSDU")
    print(AMSDU)
    print("AMPDU")
    AMPDU = AMSDU_to_AMPDU(AMSDU)
    print(AMPDU)
    print("AMPDU cifrado")
    AMPDU, claves = AMSDU_to_AMPDU_enc(AMSDU)
    print(AMPDU)
    print("AMSDU cifrado con nuestra propuesta (2 componentes)")
    Hdr, MPDU, p, x = AMSDU_enc(AMSDU)
    print(Hdr, MPDU)
    print("MSDUs descifrados del AMPDU")
    MSDUs = AMPDU_dec(AMPDU, claves)
    print(MSDUs)
    print("MSDUs descifrados con nuestra propuesta")
    AMSDUs = AMSDU_dec(Hdr, MPDU, p, x)
    print(AMSDUs)


def demo2():
    f = open('datos.DAT')
    AMSDU, MSDUs = AMSDU_gen2(f)
    print("MSDUs")
    print(MSDUs)
    print("AMSDU")
    print(AMSDU)
    print("AMPDU")
    AMPDU = AMSDU_to_AMPDU(AMSDU)
    print(AMPDU)
    print("AMPDU cifrado")
    AMPDU, claves = AMSDU_to_AMPDU_enc(AMSDU)
    print(AMPDU)
    print("AMSDU cifrado con nuestra propuesta (2 componentes)")
    Hdr, MPDU, p, x = AMSDU_enc(AMSDU)
    print(Hdr, MPDU)
    print("MSDUs descifrados del AMPDU")
    MSDUs = AMPDU_dec(AMPDU, claves)
    print(MSDUs)
    print("MSDUs descifrados con nuestra propuesta")
    AMSDUs = AMSDU_dec(Hdr, MPDU, p, x)
    print(AMSDUs)


def demo3():
    print("Vamos")
    f = open('datos2.DAT')
    AMSDUs, MSDUs = AMSDU_gen3(f)
    print("MSDUs")
    print(MSDUs)
    print("AMSDUs")
    print(AMSDUs)
    f.close()
    f = open('datos2.DAT')
    print("AMPDUs")
    AMPDUs = AMPDU_gen2(f)
    print(AMPDUs)
    f.close()
    f = open('datos2.DAT')
    print("AMPDUs cifrados y claves")
    AMPDUs, claves = AMPDU_enc2(f)
    print(AMPDUs)
    print(claves)
    print("AMSDUs cifrados con nuestra propuesta (2 componentes)")
    Hdrs = []
    MPDUs = []
    ps = []
    xs = []
    for i in range(len(AMSDUs)):
        Hdr, MPDU, p, x = AMSDU_enc(AMSDUs[i])
        Hdrs.append(Hdr)
        MPDUs.append(MPDU)
        ps.append(p)
        xs.append(x)
    print(Hdrs, MPDUs)
    print("MSDUs descifrados del AMPDU")
    MSDUs = []
    for i in range(len(AMPDUs)):
        MSDU = AMPDU_dec(AMPDUs[i], claves[i])
        MSDUs.append(MSDU)
    print(MSDUs)
    print("MSDUs descifrados con nuestra propuesta")
    AMSDUs = []
    for i in range(len(MPDUs)):
        AMSDU = AMSDU_dec(Hdrs[i], MPDUs[i], ps[i], xs[i])
        AMSDUs.append(AMSDU)
    print(AMSDUs)

