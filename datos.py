#2345678901234567890123456789012345678901234567890123456789012345678901234567890
# -*- coding: utf-8 -*-
import pickle
import math
import random
import functools
import secrets
import os, sys
from Generatramas import *
from Criptotramas import *
from random import getrandbits
import scapy.all as scapy
from datetime import datetime, timedelta

def cifrarNORMAL(key):  #
    f = open('datos3_new.DAT', "r")
    AMPDUs = AMPDU_enc2(f, key)
    print(AMPDUs)
    cifrado = AMPDUs[0].to_bytes((AMPDUs[0].bit_length() + 7) // 8, byteorder='big')
    return (cifrado, AMPDUs)
def cifrarCRT(ps,xs,Hdr):
    AMSDU, MSDUs1 = AMSDU_gen(1, 10)
    AMSDU, MSDUs2 = AMSDU_gen(1, 20)
    AMSDU, MSDUs3 = AMSDU_gen(1, 30)
    AMSDU, MSDUs4 = AMSDU_gen(1, 40)
    AMSDU, MSDUs5 = AMSDU_gen(1, 50)

    MPDU_Total=[]
    MPDU_Total.append(MPDU_gen(MSDUs5[0],2))
    MPDU_Total.append(MPDU_gen(MSDUs2[0],1))
    MPDU_Total.append(MPDU_gen(MSDUs4[0],1))
    MPDU_Total.append(MPDU_gen(MSDUs1[0],0))
    MPDU_Total.append(MPDU_gen(MSDUs3[0],1))

    mpduCi=MPDUs_enc(MPDU_Total,ps,xs,Hdr)

    mpduCi_Hex= mpduCi.to_bytes((mpduCi.bit_length() + 7) // 8,byteorder='big')

    return (mpduCi_Hex,mpduCi)


def calc_primos(num, long):
    psnew = []                      #Vector con las claves ps
    xsnew = []                      #Vector con las claves xs

    Hdr = random.getrandbits(2047)  # Cabecera común para el cifrado aleatorio
    m = 2 ** (long * 8)
    for i in list(range(num)):
        pnew = gmpy2.nextprime(m + 3)  # Calculo la clave p
        m = pnew
        psnew.append(pnew)  # y la almaceno en una lista
        xsnew.append(getrandbits(pnew.bit_length() - 1))  # Calculo la máscara aleatoria de cada diferente difrado
    return (psnew, xsnew, Hdr)
