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


def demo4(key):                                                           # Funcion paara el calculo de las simulaciones y almacenamiento de
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

    AMPDUs = AMPDU_enc2(f, velocidad, slot_time, SIFS, preambulo, ack, CW,key)
    cifrado = AMPDUs[0].to_bytes((AMPDUs[0].bit_length() + 7) // 8,byteorder='big')
    return (cifrado,AMPDUs)
    pu = open('AMPDU_CIFRADO.txt', "wb")
    pickle.dump(descifrado, pu)
    pu.close()
    f = open('AMPDU_CIFRADO.txt', "wb")
    print("despues de abrir el fichero",f.read())
    exit()
    print("CIFRADO", descifrado)
    MSDU, lapso = AMPDU_dec(AMPDUs[0], claves[0])
    descifrado=MSDU[0].to_bytes((MSDU[0].bit_len0gth()+7) // 8, byteorder='big')
    print("Descifrado",descifrado)

