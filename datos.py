#2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
import pickle
import math
import random
import functools
import secrets

# This Python file uses the following encoding: utf-8
import os, sys
from Generatramas import *
from Criptotramas import *
from random import getrandbits
import scapy.all as scapy
from datetime import datetime, timedelta
#import sympy
#from sympy.ntheory import nextprime, is_quad_residue, isprime


def cifrarNORMAL(key):  # Funcion paara el calculo de las simulaciones y almacenamiento de
    f = open('datos3_new.DAT', "r")
    AMPDUs = AMPDU_enc2(f,key)
    print(AMPDUs)
    cifrado = AMPDUs[0].to_bytes((AMPDUs[0].bit_length() + 7) // 8, byteorder='big')
    return (cifrado, AMPDUs)

def cifrarCRT():                                                           # Funcion paara el calculo de las simulaciones y almacenamiento de
                                                                       # resultados parciales, que no incluye los descifrados ni el cifrado completo de
                                                                       # nuestra propuesta

    AMSDU, MSDUs1 = AMSDU_gen(2, 10)
    AMSDU, MSDUs2 = AMSDU_gen(2, 20)
    AMSDU, MSDUs3 = AMSDU_gen(1, 30)

    MSDU_Total=[]
    MSDU_Total.append(MSDUs1[0])
    MSDU_Total.append(MSDUs1[1])
    MSDU_Total.append(MSDUs2[0])
    MSDU_Total.append(MSDUs2[1])
    MSDU_Total.append(MSDUs3[0])
    (Hdr, mpduCi, ps, xs)=AMSDU_enc(AMSDU,MSDU_Total)

    mpduCi_Hex= mpduCi.to_bytes((mpduCi.bit_length() + 7) // 8,byteorder='big')

    return (Hdr,mpduCi_Hex,mpduCi,ps,xs)


def calc_primos(num, long):
    newp = 2 ** long
    psnew = []
    xsnew = []
    pnew = []
    a = []  # Máscaras aleatorias
    n = 0  # Contador de MSDUs
    Hdr = random.getrandbits(2047)  # Cabecera común para el cifrado aleatorio
    m = 2 ** (long * 8)
    for i in list(range(num)):
        pnew = nextprime(m + 3)  # Calculo la clave p
        m = pnew
        psnew.append(pnew)  # y la almaceno en una lista
        xsnew.append(getrandbits(pnew.bit_length() - 1))  # Calculo la máscara aleatoria de cada diferente difrado

    return (psnew, xsnew, Hdr)

