#2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
import pickle
import math
import random
import binascii
import functools
import secrets

# This Python file uses the following encoding: utf-8
import os, sys
from Generatramas import *
from Criptotramas import *
from random import getrandbits

from datetime import datetime, timedelta


def nextprime(n):
	prime=0
	n+=1
	for i in range(2,int(n**0.5)+2):
		if n%i==0:
			prime=0
			break
		else:
			prime=1
	if prime==1:
		print(n)
		return
	else:
		nextprime(n)
		return

def cifrarNORMAL(key):  # Funcion paara el calculo de las simulaciones y almacenamiento de
    # resultados parciales, que no incluye los descifrados ni el cifrado completo de
    # nuestra propuesta
    tiempo_inicialb = datetime.now()
    print("Vamos")  # Comenzamos cargando los valores del escenario conforme a diferentes tecnologias
    f = open('standard.DAT', "r")
    velocidad = int(f.readline())  # b, n, g, ac = 11, 54, 300, 1300 Mbps
    slot_time = int(f.readline())  # 9, 20 = OFDM, DSSS
    SIFS = int(f.readline())  # b, n, g, ac = 10, 10, 10, 16 microsegundos
    DIFS = 2 * slot_time + SIFS
    preambulo = int(f.readline())  # b, n, g, ac = 192, 96, 96, 96 microsegundos
    ack = int(f.readline())  # 56 microsegundos
    CW = int(f.readline())
    f.close()

    f = open('datos3_new.DAT', "r")

    AMPDUs = AMPDU_enc2(f, velocidad, slot_time, SIFS, preambulo, ack, CW, key)
    cifrado = AMPDUs[0].to_bytes((AMPDUs[0].bit_length() + 7) // 8, byteorder='big')
    return (cifrado, AMPDUs)

def cifrarCRT():                                                           # Funcion paara el calculo de las simulaciones y almacenamiento de
                                                                       # resultados parciales, que no incluye los descifrados ni el cifrado completo de
                                                                       # nuestra propuesta
    tiempo_inicialb = datetime.now()
    print("Vamos")                                                     # Comenzamos cargando los valores del escenario conforme a diferentes tecnologias
    f = open('standard.DAT', "r")
    velocidad = int(f.readline())		                       # b, n, g, ac = 11, 54, 300, 1300 Mbps
    slot_time = int(f.readline())                                      # 9, 20 = OFDM, DSSS
    SIFS = int(f.readline())			                       # b, n, g, ac = 10, 10, 10, 16 microsegundos
    DIFS = 2 * slot_time + SIFS
    preambulo = int(f.readline())		                       # b, n, g, ac = 192, 96, 96, 96 microsegundos
    ack = int(f.readline())		                               # 56 microsegundos
    CW = int(f.readline())
    f.close()

    f = open('datos3_new.DAT', "r")
    AMSDU, MSDUs = AMSDU_gen(3, 10)
    print(AMSDU)

    (Hdr, mpduCi, ps, xs)=AMSDU_enc(AMSDU,MSDUs)
    print("Para transmitir",mpduCi)
    print("Claves P",ps)
    print("Claves S",xs)
    mpduCi_Hex= mpduCi.to_bytes((mpduCi.bit_length() + 7) // 8,byteorder='big')
    #AMPDUs = AMPDU_enc2(f, velocidad, slot_time, SIFS, preambulo, ack, CW,key)
    #cifrado = mpduCi.to_bytes((mpduCi.bit_length() + 7) // 8,byteorder='big')
    return (Hdr,mpduCi_Hex,mpduCi,ps,xs)

"""
key =      b'\x01\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a\x03\x0a'

radioTap = b'\x00\x00\x52\x00\x2a\x40\xd0\xa8\x20\x08\x00\xa0\x20\x08\x00\xc0\x01\x00\x00\x00\x10\x00\xcc\x15\x40' \
           b'\x01\xc0\x00\x00\x00\x00\x00\x2e\x6c\x0b\x00\x80\x00\x00\x00\xac\x2e\x00\xcd\x00\x00\x00\x00\x16\x00\x11' \
           b'\x03\xfc\xc7\x7e\x00\x53\x24\x00\x00\x80\x20\x02\x7f\x02\x00\x40\x15\xc0\x00\xbd\x01\xf6\x54\x25\x01\x02\x00\x01\x00\x00\x00'
#print("clave",key)

Hdr,mpduCi_Hex,mpduCi,ps,xs=cifrarCRT()
MSDUs=AMSDU_dec(Hdr, mpduCi, ps, xs)
for i in MSDUs:
    print(i)
exit()
print("radio",radioTap)
prueba=radioTap+AMPDU
print(size(AMPDU))
print("AMPDU",AMPDU)
MSDU, lapso = AMPDU_dec(int.from_bytes(AMPDU, byteorder='big'), key)
descifrado=MSDU[0].to_bytes((MSDU[0].bit_length()+7) // 8, byteorder='big')
print("Descifrado",descifrado)"""
