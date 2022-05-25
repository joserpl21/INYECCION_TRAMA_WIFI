#2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
import binascii
import random
import secrets
from datetime import datetime, timedelta
from scapy.utils import hexdump


def MSDU_gen (longitud_payload, no_ultimo):                                # Función para quenerar un MSDU de datos aleatorio, pero con cabeceras correctas
    DA =b'\x00\xc0\xca\xa4\x73\x7b'                                # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    SA =b'\x00\xc0\xca\xa4\x73\x7c'                                         # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Payload = secrets.token_bytes(longitud_payload)                          # Elegimos una carga aleatoria de tamaño fijado en la entrada
    Mesh_flags = b'\x40'                                                   # Supondremos que necesitamos dos direcciones más
    Mesh_TTL = secrets.token_bytes(1)                                        # TTL dentro de la red mesh
    Mesh_sequence_number = secrets.token_bytes(4)                            # Número de secuencia
    #cambiamos esto
    Address5 = secrets.token_bytes(6)                                         # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Address6 = secrets.token_bytes(6)                                         # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    #Tener en cuenta si se va acumular dentro de AMSDU -> Mesh_control solo tiene sentido cuando lo vas a agregar en un AMSDU
    #En un AMPDU no es ncecesario el mes_control
    #print("MSDU_gen ", longitud_payload)
    Mesh_control = Mesh_flags + Mesh_TTL + Mesh_sequence_number + Address5 + Address6
    Payload=b'\x8F\x1E\x55\x75\x63\x90\x31\x21\xFC\x89'
    Imponible = DA + SA + longitud_payload.to_bytes(2, byteorder='big') + Payload

    longitud_padding = 4 - (len(Imponible)%4)                             # Calculamos la longitud del padding

    if ((longitud_padding != 4) and (no_ultimo == 'true')):
        MSDU = Imponible + secrets.token_bytes(longitud_padding)
        print("e")
    else: MSDU = Imponible                                                 # Añadimos el padding si lo necesita

    print("MSDU: ")
    print(hexdump(MSDU))
    a=int.from_bytes(MSDU, byteorder='big')
    #print("MSDU_DECIMAL:",a)
    return a

def MSDU_gen2 (Payload):                                                   # Función para quenerar un MSDU de datos a partir de un payload determinado
    longitud_payload = (7 + Payload.bit_length()) // 8                     # Calculamos la longitud en bytes del payload
    DA = b'\xAA' + secrets.token_bytes(5)                                     # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    SA = secrets.token_bytes(6)                                               # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Mesh_flags = b'\x40'                                                   # Supondremos que necesitamos dos direcciones más
    Mesh_TTL = secrets.token_bytes(1)                                         # TTL dentro de la red mesh
    Mesh_sequence_number = secrets.token_bytes(4)                             # Número de secuencia
    Address5 = secrets.token_bytes(6)                                         # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Address6 = secrets.token_bytes(6)                                         # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
                                                                           # Con estos últimos datos calculamos el Mesh Control que luego adjuntamos al MSDU
    Mesh_control = Mesh_flags + Mesh_TTL + Mesh_sequence_number + Address5 + Address6
    MSDU = (DA + SA + longitud_payload.to_bytes(2, byteorder='big') + Mesh_control
          + Payload.to_bytes(longitud_payload, byteorder='big'))
    return int.from_bytes(MSDU, byteorder='big')


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
        MSDUs.append(MSDU >> (8 * pad))
        AMSDU = (AMSDU << (8 * bytes_resultantes)) ^ MSDU
    MSDU = MSDU_gen(longitud_payload, 'false')                            # El ultimo MSDU sin padding
    MSDUs.append(MSDU)
    AMSDU = (AMSDU << (8 * ((7 + MSDU.bit_length()) // 8))) ^ MSDU
    return (AMSDU, MSDUs)

def AMSDU_gen2 (f):                                                       # Función para la generación de un AMSDU a partir de los datos de un fichero
                                                                          # donde vienen las longitudes de los MSDUs en octetos.
    AMSDU = 0                                                             # Inicializacion del AMSDU
    MSDUs = []
    longitud = int(f.readline())
    longituds = f.readline()
    filtro1 = (1 << 112)- 1                                               # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    while (longituds != ''):                                              # Lo constrímos adjuntando cada MSDU
        MSDU = MSDU_gen(longitud, 'true')
        bytes_resultantes = (7 + MSDU.bit_length()) // 8
        cabecera = (MSDU & (filtro1 << (8 * (bytes_resultantes - 14)))) >> (8 * (bytes_resultantes - 14))
                                                                          # Calculamos la cabecera
        longitud = cabecera & filtro2                                     # Y la longitud del MSDU
        pad = 4 - (longitud % 4)
        if pad == 4: pad = 0
        MSDUs.append(MSDU >> (8 * pad))
        AMSDU = (AMSDU << (8 * bytes_resultantes)) ^ MSDU
        longitud = int(longituds)
        longituds = f.readline()
    MSDU = MSDU_gen(longitud, 'false')                             # El ultimo MSDU sin padding
    MSDUs.append(MSDU)
    AMSDU = (AMSDU << (8 * ((7 + MSDU.bit_length()) // 8))) ^ MSDU
    return (AMSDU, MSDUs)

def AMSDU_gen3 (f, velocidad, slot_time, SIFS, preambulo, ack, CW):       # Función para la generación de AMSDUs a partir de datos leídos de un fichero.
                                                                          # Primero el tamaño del MSDU y luego los microsegundos que han pasado tras la
                                                                          # llegada del anterior
    DIFS = 2 * slot_time + SIFS
    tope_t = timedelta(microseconds = 20000)                              # Tope temporal
    tope_m = 7965                                                         # Tope AMPDU (7965)
    tope_d = 2304                                                         # Tope AMSDU (2304)
    AMSDUs = []                                                           # Inicializacion de los AMSDUs
    MSDUs = []                                                            # Inicialización de los MSDUs de cada AMSDU
    lapsos = []
    lanzamientos = []                                                     # Tiempo en microsegundos entre los finales de las transmisiones de dos AMSDUs
    agregados = []                                                        # Cantidad de MSDUs que hay en cada AMSDU
    tx = timedelta(0)                                                     # Tiempo de transmisión acumulado
    filtro1 = (1 << 112)- 1                                               # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    ultimo = 'false'                                                      # Booleano que controla si he llegado al ultimo MSDU del AMSDU
    final = 'false'                                                       # Booleano que controla si he llegado al final del fichero
    i = 0                                                                 # Contador de MSDUs almacenados
    retraso = timedelta(0)                                                # Tiempo de espera que ha pasado desde la llegada del ultimo paquete que ha sido
                                                                          # transmitido
    longitudes_AMSDU = []                                                 # Inicializamos longitudes del AMSDU
    AMSDU_acumulado_l = 0                                                 # Inicializamos la longitud acumulada del AMSDU
    AMSDU_acumulado_t = timedelta(0)                                      # Inicializamos el tiempo de retardo para la creacion del AMSDU
    while (final == 'false'):                                             # Parar si hemos llegado al final del fichero
        while (ultimo == 'false'):                                        # Parar si hemos llegado al final del AMSDU
            lectura = f.readline()                                        # Leo la presunta longitud del MSDU
            if (lectura == ''):
                final = 'true'
                ultimo = 'true'
            else:
                longitud_nuevo = int(lectura)                             # Leo la longitud del candidato
                tiempo_nuevo = timedelta(microseconds = int(f.readline()))# y el tiempo de llegada desde la anterior
                if (tiempo_nuevo > retraso): paso = tiempo_nuevo - retraso
                else: paso = tiempo_nuevo
                if (((AMSDU_acumulado_l + longitud_nuevo) > tope_d) or ((AMSDU_acumulado_t + paso) > tope_t)): ultimo = 'true'
                else:
                    if retraso > tiempo_nuevo:                            # Quitamos del retraso el tiempo de retardo
                        retraso = retraso - tiempo_nuevo
                        tiempo_nuevo = timedelta(0)
                    else:                                                 # o viceversa
                        tiempo_nuevo = tiempo_nuevo - retraso
                        retraso = timedelta(0)
                    AMSDU_acumulado_l += longitud_nuevo
                    AMSDU_acumulado_t += tiempo_nuevo
                    longitudes_AMSDU.append(longitud_nuevo)
                    i += 1

        AMSDU = 0                                                         # Incializamos el AMSDU
        for j in range(i - 1):
            MSDU = MSDU_gen(longitudes_AMSDU[j], 'true')                  # Generamos el MSDU correspondiente
            bytes_resultantes = (7 + MSDU.bit_length()) // 8
            cabecera = (MSDU & (filtro1 << (8 * (bytes_resultantes - 14)))) >> (8 * (bytes_resultantes - 14))
                                                                          # Calculamos la cabecera
            longitudes = cabecera & filtro2                               # Y la longitud del MSDU
            pad = 4 - (longitudes % 4)
            if pad == 4: pad = 0
            MSDUs.append(MSDU >> (8 * pad))
            AMSDU = (AMSDU << (8 * bytes_resultantes)) ^ MSDU             # Agregamos el MSDU
        MSDU = MSDU_gen(longitudes_AMSDU[i-1], 'false')                     # El ultimo MSDU sin padding
        MSDUs.append(MSDU)
        AMSDU = (AMSDU << (8 * ((7 + MSDU.bit_length()) // 8))) ^ MSDU
        MPDU = MPDU_gen(AMSDU)
        AMSDUs.append(AMSDU)                                              # Almacenamos el AMSDU
#        transmision = (round((MPDU.bit_length() / velocidad)) + 2 * preambulo + ack + SIFS
#                     + DIFS + (int.from_bytes(secret.token_bytes(2), byteorder = 'big') >> (16 - CW)) * slot_time)
        transmision = (round((MPDU.bit_length() + 48 * 8) * (10 ** 6)/(velocidad << 20)) + 4 * preambulo + 3 * SIFS
                     + DIFS + (1 << CW) * slot_time)

        if tx < timedelta(microseconds = 999999999):                                                                # Calculamos el tiempo de transmision del AMSDU
            tx += timedelta(microseconds = transmision)                       # Lo acumulamos
        if ((final == 'true') or ((final == 'false') and ((AMSDU_acumulado_l + longitud_nuevo) > tope_d))): lanzamiento = AMSDU_acumulado_t
        else: lanzamiento = tope_t
#        lanzamiento += lapso
        lanzamiento += timedelta(microseconds = transmision)              # Calculamos el instante de transmisión tomando como referencia al anterior
#        retraso += lapso
        if retraso < timedelta(microseconds = 999999999):
            retraso += timedelta(microseconds = transmision)
#        print(retraso)
        lanzamientos.append(lanzamiento)
        agregados.append(i)                                               # Almacenamos la cantidad de MSDU de este AMSDU
        i = 0
        if (final == 'false'):
            longitudes_AMSDU = []
            AMSDU_acumulado_l = longitud_nuevo
            if retraso > tiempo_nuevo:                                    # Quitamos del retraso el tiempo de retardo
                retraso = retraso - tiempo_nuevo
                tiempo_nuevo = timedelta(0)
            else:                                                         # o viceversa
                tiempo_nuevo = tiempo_nuevo - retraso
                retraso = timedelta(0)
            AMSDU_acumulado_t = tiempo_nuevo
            longitudes_AMSDU.append(longitud_nuevo)
            i += 1
            ultimo = 'false'
    return (AMSDUs, MSDUs, lapsos, lanzamientos, agregados, tx)



def AMSDU_gen4 (f, velocidad, slot_time, SIFS, preambulo, ack, CW):   # Función para la generación y transmisión del escenario básico
    DIFS = 2 * slot_time + SIFS
    tope_t = timedelta(microseconds = 20000)                          # Tope temporal
    tope_m = 7965                                                     # Tope AMPDU (7965)
    tope_d = 2304                                                     # Tope AMSDU (2304)
    MPDUs = []                                                        # Inicialización de la lista de MPDUs
    lanzamientos = []                                                 # Inicialización de la lista de tiempos entre transmisiones
    tx = timedelta(0)                                                 # Inicialización del acumulado de tiempos de transmisión
    longitud = int(f.readline())                                      # Tamaño del primer paquete
    if longitud > tope_d : longitud = tope_d - 1
    delta_time = timedelta(microseconds = int(f.readline()))          # Primer tiempo entre paquetes
    retraso = timedelta(0)                                            # Inicialización frl tiempo de retraso
    longituds = f.readline()                                          # Longitud del siguiente paquete
    while (longituds != ''):                                          # Hasta el final del fichero
        MPDU = MPDU_gen(MSDU_gen(longitud, 'false'))                  # Construyo el MPDU
        MPDUs.append(MPDU)                                            # Y lo almaceno

        longitud = int(longituds)                                    # Actualizo datos del siguiente paquete
        if longitud > tope_d : longitud = tope_d - 1
        longituds = f.readline()


    MPDU = MPDU_gen(MSDU_gen(longitud, 'false'))                      # Construyo el ultimo MPDU

    MPDUs.append(MPDU)                                                # Y lo almaceno
    print("Tamaño final",str(len(MPDUs)))

    return (MPDUs)


def gen_retardos (f, velocidad, slot_time, SIFS, preambulo, ack, CW, k):  # Función para la generación de AMSDUs a partir de datos leídos de un fichero.
                                                                          # Primero el tamaño del MSDU y luego los microsegundos que han pasado tras la
                                                                          # llegada del anterior
    DIFS = 2 * slot_time + SIFS
    tope_t = timedelta(microseconds = 20000)                              # Tope temporal
    tope_m = 7965                                                         # Tope AMPDU (7965)
    tope_d = 2304                                                         # Tope AMSDU (2304)
    AMSDUs = []                                                           # Inicializacion de los AMSDUs
    AMPDUs = []                                                           # Inicializacion de los AMPDUs
    MSDUs = []                                                            # Inicialización de los MSDUs de cada AMSDU
    lanzamientos = []                                                     # Tiempo en microsegundos entre los finales de las transmisiones de dos AMSDUs
    lanzamientoss = []                                                    # Tiempo en microsegundos entre los finales de las transmisiones de dos AMPDUs
    tx = timedelta(0)                                                     # Tiempo de transmisión acumulado para AMSDUs
    txx = timedelta(0)                                                    # Tiempo de transmisión acumulado para AMPDUs
    filtro1 = (1 << 112)- 1                                               # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    retraso = timedelta(0)                                                # Tiempo de espera que ha pasado desde la llegada del ultimos paquetes que han
    retrasos = timedelta(0)                                               # sido transmitidos
    AMSDU_acumulado_t = timedelta(0)                                      # Inicializamos el tiempo de retardo para la creacion del AMSDU
    AMPDU_acumulado_t = timedelta(0)                                      # Inicializamos el tiempo de retardo para la creacion del AMPDU
    lectura = f.readline()
    if (lectura == ''): final = 'true'
    else: final = 'false'
    while (final == 'false'):                                             # Parar si hemos llegado al final del fichero
        AMSDU = 0
        for i in range(k - 1) :                                           # Parar si hemos llegado al final del AMSDU
            longitud_nuevo = int(lectura)
            tiempo_nuevo = timedelta(microseconds = int(f.readline()))    # y el tiempo de llegada desde la anterior
            tiempo_nuevos = tiempo_nuevo
            if retraso > tiempo_nuevo:                                    # Quitamos del retraso el tiempo de retardo
                retraso = retraso - tiempo_nuevo
                tiempo_nuevo = timedelta(0)
            else:                                                 # o viceversa
                tiempo_nuevo = tiempo_nuevo - retraso
                retraso = timedelta(0)
            AMSDU_acumulado_t += tiempo_nuevo
            if retrasos > tiempo_nuevos:                                    # Quitamos del retraso el tiempo de retardo
                retrasos = retrasos - tiempo_nuevos
                tiempo_nuevos = timedelta(0)
            else:                                                 # o viceversa
                tiempo_nuevos = tiempo_nuevos - retrasos
                retrasos = timedelta(0)
            AMPDU_acumulado_t += tiempo_nuevos
            MSDU = MSDU_gen(longitud_nuevo, 'true')                  # Generamos el MSDU correspondiente
            bytes_resultantes = (7 + MSDU.bit_length()) // 8
            cabecera = (MSDU & (filtro1 << (8 * (bytes_resultantes - 14)))) >> (8 * (bytes_resultantes - 14))
                                                                          # Calculamos la cabecera
            longitudes = cabecera & filtro2                               # Y la longitud del MSDU
            pad = 4 - (longitudes % 4)
            if pad == 4: pad = 0
            MSDUs.append(MSDU >> (8 * pad))
            AMSDU = (AMSDU << (8 * bytes_resultantes)) ^ MSDU             # Agregamos el MSDU
            lectura = f.readline()
        MSDU = MSDU_gen(int(lectura), 'false')                   # El ultimo MSDU sin padding
        MSDUs.append(MSDU)
        AMSDU = (AMSDU << (8 * ((7 + MSDU.bit_length()) // 8))) ^ MSDU
        MPDU = MPDU_gen(AMSDU)
        AMSDUs.append(AMSDU)                                              # Almacenamos el AMSDU
        AMPDU = AMSDU_to_AMPDU(AMSDU)
        AMPDUs.append(AMPDU)                                              # Almacenamos el AMPDU
        tiempo_nuevo = timedelta(microseconds = int(f.readline()))
        tiempo_nuevos = tiempo_nuevo
        if retraso > tiempo_nuevo:                                        # Quitamos del retraso el tiempo de retardo
            retraso = retraso - tiempo_nuevo
            tiempo_nuevo = timedelta(0)
        else:                                                             # o viceversa
            tiempo_nuevo = tiempo_nuevo - retraso
            retraso = timedelta(0)
        AMSDU_acumulado_t += tiempo_nuevo
        if retrasos > tiempo_nuevos:                                      # Quitamos del retraso el tiempo de retardo
            retrasos = retrasos - tiempo_nuevos
            tiempo_nuevos = timedelta(0)
        else:                                                             # o viceversa
            tiempo_nuevos = tiempo_nuevos - retrasos
            retrasos = timedelta(0)
        AMPDU_acumulado_t += tiempo_nuevos
        transmision = (round((MPDU.bit_length() / velocidad)) + 2 * preambulo + ack + SIFS
                      + DIFS + (int.from_bytes(secrets.token_bytes(2), byteorder = 'big') >> (16 - CW)) * slot_time)
#        transmision = (round((MPDU.bit_length() + 48 * 8) * (10 ** 6)/(velocidad << 20)) + 4 * preambulo + 3 * SIFS
#                     + DIFS + (1 << CW) * slot_time)
                                                                          # Calculamos el tiempo de transmision del AMSDU
        tx += timedelta(microseconds = transmision)                       # Lo acumulamos
        transmisions = (round((AMPDU.bit_length() / velocidad)) + 2 * preambulo + ack + SIFS
                      + DIFS + (int.from_bytes(secrets.token_bytes(2), byteorder = 'big') >> (16 - CW)) * slot_time)
#        transmisions = (round((AMPDU.bit_length() + 48 * 8) * (10 ** 6)/(velocidad << 20)) + 4 * preambulo + 3 * SIFS
#                      + DIFS + (1 << CW) * slot_time)
                                                                          # Calculamos el tiempo de transmision del AMPDU
        txx += timedelta(microseconds = transmisions)                     # Lo acumulamos
        lectura = f.readline()
        if (lectura == ''): final = 'true'
        lanzamiento = AMSDU_acumulado_t
        lanzamiento += timedelta(microseconds = transmision)              # Calculamos el instante de transmisión tomando como referencia al anterior
        retraso += timedelta(microseconds = transmision)
        lanzamientos.append(lanzamiento)
        lanzamiento = AMPDU_acumulado_t
        lanzamiento += timedelta(microseconds = transmisions)             # Calculamos el instante de transmisión tomando como referencia al anterior
        retrasos += timedelta(microseconds = transmisions)
        lanzamientoss.append(lanzamiento)
        AMSDU_acumulado_t = timedelta(0)
        AMPDU_acumulado_t = timedelta(0)
    return (AMPDUs, AMSDUs, MSDUs, lanzamientos, lanzamientoss, tx, txx)



def MPDU_gen (MSDU):                                                      # Función para generar un MPDFU a partir de un MSDU
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
    Address1 = b'\x00\xc0\xca\xa4\x73\x7b'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Address2 = b'\x00\xc0\xca\xa4\x73\x7c'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Address3 = b'\x00\xc0\xca\xa4\x73\x7c'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
    Sequence_control = b'\x00\x00'                                        # Supondremos sin fragmentación del MSDU
    Address4 = b'\x00\xc0\xca\xa4\x73\x7b'                                        # No sabemos a priori al valor de este campo, así que elgimos un valor aleatorio
                                                                          # No incluimos los byates de QoS y de control HT porque hemos considerado
                                                                          # que la trama va a ser de datos.
    Imponible = (frame_control + Duration + Address1 + Address2 + Address3 + Sequence_control
               + Address4 + MSDU.to_bytes((MSDU.bit_length() + 7) // 8, byteorder='big'))
    FCS = binascii.crc32(Imponible)
    MPDU = Imponible + FCS.to_bytes(4, byteorder='big')                   # Adjuntamos el CRC
    return int.from_bytes(MPDU, byteorder='big')




def AMPDU_gen (longitud_agregado, longitud_payload):                     # Función para generar un AMPDU con MSDUs aleatorios
    AMPDU = 0                                                            # Inicializacion del AMPDU
    for i in range (longitud_agregado - 1):                              # Construimos agregando los MPDUs
        MSDU = MSDU_gen(longitud_payload, 'false')                       # Construímos cada uno de los MSDU's que componenen la MPDU,
                                                                         # aclarando que no es el último de ese AMPDU por el tema del padding
        MPDU = MPDU_gen(MSDU)                                            # Para cada MSDU construimos su correspondiente AMPDU
                                                                         # Calculamos el correspondiente delimitador, fijando los bits reservados a 1.
        Delimiter = (15 << 12) ^ ((7 + MPDU.bit_length()) // 8)
        FCS = crc8(Delimiter)
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = (((AMPDU << 32) ^ Delimiter) << MPDU.bit_length()) ^ MPDU # Calculamos la longitud del padding y lo adjuntamos también
        longitud_padding = 4 - (1 + MPDU.bit_length()//8)%4
        if longitud_padding != 4: AMPDU = ((AMPDU << (8*longitud_padding))
                                         ^ (int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big')))
                                                                          # Para el último MPDU no se necesita padding,
                                                                          # así que repetimos el proceso, excepto para el padding y damos la respuesta
    MSDU = MSDU_gen(longitud_payload, 'true')
    MPDU = MPDU_gen(MSDU)
    Delimiter = (15 << 12) ^ ((7 + MPDU.bit_length()) // 8)
    FCS = crc8(Delimiter)
    Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
    AMPDU = (((AMPDU << 32) ^ Delimiter) << MPDU.bit_length()) ^ MPDU
    return AMPDU                                                         # Devolvemos el AMPDU

def AMPDU_gen2 (f, velocidad, slot_time, SIFS, preambulo, ack, CW):       # Función para generar un AMPDU con MSDUs aleatorios
    DIFS = 2 * slot_time + SIFS
    tope_t = timedelta(microseconds = 20000)                              # Tope temporal
    tope_m = 7965                                                         # Tope AMPDU (7965)
    tope_d = 2304                                                         # Tope AMSDU (2304)
    AMPDUs = []                                                           # Inicializacion de los AMSDUs
    lapsos = []
    lanzamientos = []                                                     # Tiempo en microsegundos entre los finales de las transmisiones de dos AMSDUs
    agregados = []                                                        # Cantidad de MPDUs que hay en cada AMPDU
    tx = timedelta(0)                                                     # Tiempo de transmisión acumulado
    ultimo = 'false'                                                      # Booleano que controla si he llegado al ultimo MPDU del AMPDU
    final = 'false'                                                       # Booleano que controla si he llegado al final del fichero
    i = 0                                                                 # Contador de MPDUs almacenados
    retraso = timedelta(0)                                                # Tiempo de espera que ha pasado desde la llegada del ultimo paquete que ha sido
                                                                          # transmitido
    longitudes_AMPDU = []                                                 # Inicializamos longitudes del AMPDU
    AMPDU_acumulado_l = 0                                                 # Inicializamos la longitud acumulada del AMPDU
    AMPDU_acumulado_t = timedelta(0)                                      # Inicializamos el tiempo de retardo para la creacion del AMPDU
    while (final == 'false'):                                             # Parar si hemos llegado al final del fichero
        while (ultimo == 'false'):                                        # Parar si hemos llegado al final del AMPDU
            lectura = f.readline()                                        # Leo la presunta longitud del MSDU
            if (lectura == ''):
                final = 'true'
                ultimo = 'true'
            else:
                longitud_nuevo = int(lectura)                             # Leo la longitud del candidato
                tiempo_nuevo = timedelta(microseconds = int(f.readline()))# y el tiempo de llegada desde la anterior
                if (tiempo_nuevo > retraso): paso = tiempo_nuevo - retraso
                else: paso = tiempo_nuevo
                if (((AMPDU_acumulado_l + longitud_nuevo) > tope_d) or ((AMPDU_acumulado_t + paso) > tope_t)): ultimo = 'true'
                else:
                    if retraso > tiempo_nuevo:                            # Quitamos del retraso el tiempo de retardo
                        retraso = retraso - tiempo_nuevo
                        tiempo_nuevo = timedelta(0)
                    else:                                                 # o viceversa
                        tiempo_nuevo = tiempo_nuevo - retraso
                        retraso = timedelta(0)
                    AMPDU_acumulado_l += longitud_nuevo
                    AMPDU_acumulado_t += tiempo_nuevo
                    longitudes_AMPDU.append(longitud_nuevo)
                    i += 1

        AMPDU = 0                                                         # Incializamos el AMPDU
        for j in range(i - 1):

            MSDU = MSDU_gen(longitudes_AMPDU[j], 'true')                # Construímos cada uno de los MSDU's que componenen la MPDU,
                                                                        # aclarando que no es el último de ese AMPDU por el tema del padding
            MPDU = MPDU_gen(MSDU)                                       # Para cada MSDU construimos su correspondiente MPDU
                                                                        # Calculamos el correspondiente delimitador, fijando los bits reservados a 1.
            Delimiter = (15 << 12) ^ ((7 + MPDU.bit_length()) // 8)
            FCS = crc8(Delimiter)
            Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
            AMPDU = (((AMPDU << 32) ^ Delimiter) << MPDU.bit_length()) ^ MPDU
                                                                        # Calculamos la longitud del padding y lo adjuntamos también
            longitud_padding = 4 - (1 + MPDU.bit_length()//8)%4
            if longitud_padding != 4: AMPDU = ((AMPDU << (8*longitud_padding))
                                             ^ (int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big')))

        MSDU = MSDU_gen(longitudes_AMPDU[i-1], 'false')                 # Construímos el último de los MSDU's que componenen la MPDU,
        MPDU = MPDU_gen(MSDU)                                           # Construimos su correspondiente MPDU                                                                                                                        # Calculamos el correspondiente delimitador, fijando los bits reservados a 1. Etc.
        Delimiter = (15 << 12) ^ ((7 + MPDU.bit_length()) // 8)
        FCS = crc8(Delimiter)
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = (((AMPDU << 32) ^ Delimiter) << MPDU.bit_length()) ^ MPDU
        AMPDUs.append(AMPDU)                                           # Almacenamos el AMPDU

#??
#        transmision = (round((AMPDU.bit_length() / velocidad)) + 2 * preambulo + ack + SIFS
#                     + DIFS + (int.from_bytes(secrets.token_bytes(2), byteorder = 'big') >> (16 - CW)) * slot_time)
        transmision = (round((AMPDU.bit_length() + 48 * 8) * (10 ** 6)/(velocidad << 20)) + 4 * preambulo + 3 * SIFS
                     + DIFS + (1 << CW) * slot_time)
                                                                          # Calculamos el tiempo de transmision del AMPDU
        if tx < timedelta(microseconds = 999999999):
            tx += timedelta(microseconds = transmision)                       # Lo acumulamos
        if ((final == 'true') or ((final == 'false') and ((AMPDU_acumulado_l + longitud_nuevo) > tope_d))): lanzamiento = AMPDU_acumulado_t
        else: lanzamiento = tope_t
#        lanzamiento += lapso
        lanzamiento += timedelta(microseconds = transmision)              # Calculamos el instante de transmisión tomando como referencia al anterior
#        retraso += lapso
        if retraso < timedelta(microseconds = 999999999):
            retraso += timedelta(microseconds = transmision)
#        print(retraso)
        lanzamientos.append(lanzamiento)
        agregados.append(i)                                               # Almacenamos la cantidad de MPDU de este AMPDU
        i = 0
        if (final == 'false'):
            longitudes_AMPDU = []
            AMPDU_acumulado_l = longitud_nuevo
            if retraso > tiempo_nuevo:                                    # Quitamos del retraso el tiempo de retardo
                retraso = retraso - tiempo_nuevo
                tiempo_nuevo = timedelta(0)
            else:                                                         # o viceversa
                tiempo_nuevo = tiempo_nuevo - retraso
                retraso = timedelta(0)
            AMPDU_acumulado_t = tiempo_nuevo
            longitudes_AMPDU.append(longitud_nuevo)
            i += 1
            ultimo = 'false'
    return (AMPDUs, lapsos, lanzamientos, agregados, tx)


def AMSDU_to_AMPDU (AMSDU):                                              # Función para generar un AMPDU a partir de un AMSDU
    AMPDU = 0                                                            # Inicializacion del AMPDU
    filtro1 = (1 << 112)- 1                                              # Filtros para leer los campos de la cabecera
    filtro2 = (1 << 16) - 1
    while (AMSDU != 0):                                                  # Vamos a recorrer el AMSDU hasta que se vacíe
        bytes_restantes = (7 + AMSDU.bit_length()) // 8
        cabecera = (AMSDU & (filtro1 << (8 * (bytes_restantes - 14)))) >> (8 * (bytes_restantes - 14))
                                                                         # Calculamos la cabecera
        longitud = cabecera & filtro2                                    # Y la longitud del MSDU
        pad = 4 - (longitud % 4)
        if ((pad == 4) or ((8*longitud) >= (AMSDU.bit_length() - 256))): pad = 0
                                                                         # Determinamos si el MSDU contiene padding
        filtro = ((1 << 8*(14 + 18 + longitud + pad)) - 1) << (8 * (bytes_restantes - (14 + 18 + longitud + pad)))
                                                                         # He sumado 18 bytes del Mesh Control
        MSDU_aux = (AMSDU & filtro) >> (8 * (bytes_restantes - (14 + 18 + longitud + pad)))
                                                                         # Calculo el MSDU y lo quito del agregado
        AMSDU = AMSDU ^ (MSDU_aux << (8*(bytes_restantes - (14 + 18 + longitud + pad))))
        MPDU = MPDU_gen(MSDU_aux >> (8*pad))                             # Para cada MSDU construimos su correspondiente MPDU
                                                                         # Calculamos el correspondiente delimitador, fijando los bits reservados a 1.
        Delimiter = (15 << 12) ^ ((7 + MPDU.bit_length()) // 8)
        FCS = crc8(Delimiter)
        Delimiter = (((Delimiter << 8) ^ FCS) << 8) ^ int.from_bytes(b'\x4e', byteorder='big')
        AMPDU = ((AMPDU << 32) ^ Delimiter) << (8 * ((7 + MPDU.bit_length()) // 8)) ^ MPDU # Calculamos la longitud del padding y lo adjuntamos también
        longitud_padding = 4 - ((7 + MPDU.bit_length()//8)%4)
        if ((longitud_padding != 4) and ((8*longitud) >= (AMSDU.bit_length() - 256))):
          AMPDU = ((AMPDU << (8*longitud_padding)) ^ (int.from_bytes(secrets.token_bytes(longitud_padding), byteorder='big')))
    return AMPDU                                                         # Devolvemos el AMPDU



def crc8(data):                                                           # Función para calcular el CRC8 de las cabececeras
    n = data.bit_length()
    divisor = 263 << (n - 9)
    tope = (1 << (n-1)) - 1
    for i in range(n, 8, -1):
          if data >= tope: data = data ^ divisor
          divisor = divisor >> 1
          tope = tope >> 1
    return data
