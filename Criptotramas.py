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
import zlib
#pip3 install pycryptodome
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
        MPDU = MPDU_gen(MSDU)
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

def AMSDU_enc(AMSDU,MSDU):  # Función que cifra un AMSDU con el teorema chino del resto (CRT) - modificacion con poner un AMPDU
    MSDUs = []  # Creamos una lista para los MSDUs "desentramados"
    ps=[179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859, 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224138297, 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224139329, 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224139931, 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224140927]
    xs=[48020969358492679318863735534997180836170863661985692071726993034945946832746279123965114000283661643882335792316790291443804567542156954397126787358641608186232956803797411368596530278760639421169306736267892649484550224775691166079443632627835531814801183167613013316799479791100311001779564647278762633541, 127883885709200231651531696232276839856603698464079978162414254212552597368183998395595141173511918672840654695565973660314451967937317112761430727264115716645572906988214807983849346662331766753390640744157059955164510753085793695438864559716346726908438044825624280598567036601163766418531414128353078978638, 60289359314090800190445649839761805182970713176385665388725978516802749898936200978117637449999387343946013900696217422976139698441294066585518338866803586379416850032284845930575174301972207267802422925588618636466646877561627583887286087568338746101684315058628918456593728486373451814620465060602382402468, 51062515417529277526945128307594259195486583110720791748540527192733834855416286031598772289032860827130947052526578700038323006416125243222827197411066586011800102679460005522707833206714097782604925269619912549204174317400963779664751820664615965803468126412262664097293951929592234969612116409114015825578, 146257116770323725965981324897286806168341858221148034876128508055102276499603303673631985324947439905458689639993428344141525575761914704312791227363983881912239665462812106881036926673016654640403838713144881828493708775552838727007407036048569996466164739591282939912499909155976806770375009287739246838950]
    Hdr=7015584123041823511118356678864494506768429930840562545412148912629539878530091445544494631192638152240459158965235731000721523670511550392942548294504219396133626645099589512357952193528605825058086441176243751682379295569249313773568751237886215641000467415006110244950130540312306619248720671236940046238679212810167963687550581330171336308448314363185605352228010853943136978888629243552551778193591255476672405341809430793385234125754836989144448914450601198758268864924477642352421976246125273639878000740300058462358751868730635682212696033092630859757874070738295951604848754707337975489220747048022945315863
    #ps = [10008386490508017356935324557823723380245938117, 10008386490508017356935324557823764747562867313,
    #      39095259728546942800528611553999172820340319]
    #xs = [2446136256064064230830599030587722500704580507, 2862049875671410165813468988774253092617925367,
    #      20204778326880020921067333045180365703523114]
    #Hdr = 53832240119234469865366958933431868004436000620489566332772059013971303354028870238851359689585525302420448035012180261737031931572828023145146547494106606111067533621167395455709909979463394966562335396255525175694849640350262659402566793148239236082127735630238595293458964092099081884990016334315489195020
    a = []  # Máscaras aleatorias
    #ps = []
    #xs = []
    n = 0  # Contador de MSDUs
    #Hdr = random.getrandbits(1023)  # Cabecera común para el cifrado aleatorio
    #Hdr = 15954397600484676080445144553223529992678013943537230069224121000855699303061777531981089406222510881421088752704688036147253082732657897862191895053631674856772128322391273493214154863018969779796561231280601263793302777253129776032382760813815413222441888256216530367314241202928278526289479100743111536202
    # print("HDR", Hdr)
    filtro1 = (1 << 112)   -1  # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    tiempo_inicial = datetime.now()
    for i in MSDU:
        #print("MSDU ANTES DE ENCRIPTAR", i)
        #print(type(i))
        #p = nextprime(i + 3)  # Calculo la clave p
        #ps.append(p)  # y la almaceno en una lista
        #xs.append(getrandbits(p.bit_length() - 1))  # Calculo la máscara aleatoria de cada diferente difrado
        a.append((i + pow(Hdr, xs[n], ps[n])) % ps[n])  # y enmascaro el MSDU
        #print(a)
        n = n + 1
    #print(ps)
    return (Hdr, chinese_remainder(ps, a), ps,
            xs)  # Devuelvo la cabecera aleatoria y un MPDU cifrado con el CRT


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

