#!/usr/bin/python3
from ctypes import *
import math

class WrappedSCP:
    def __init__(self, bufSize=512):
        self.bufSize = bufSize
        self.libFilePath = "/usr/lib/x86_64-linux-gnu/libscpdb_agent.so"
        self.iniFilePath = "/usr/share/gooroom/BA-SCP/Config/scpdb_agent.ini"
        self.clib = cdll.LoadLibrary(self.libFilePath)

    def WSCP_EncB64(self, str_plain):
        resultEnc = []
        enc = create_string_buffer(self.bufSize*2)
        encLen = c_int()
        for i in range(math.ceil(len(str_plain)/self.bufSize)):
            plain = create_string_buffer(bytes(str_plain[i*self.bufSize : (i+1)*self.bufSize], "utf8"))
            print(plain)
            ret = self.clib.SCP_EncB64(self.iniFilePath.encode(), b'KEY1', plain, len(plain.value), enc, byref(encLen), sizeof(enc))
            if ret != 0 :
                print("WSCP_EncB64 error :", ret)
                return ret, resultEnc
            resultEnc.append(enc.value.decode('utf-8'))
        return ret, resultEnc

    def WSCP_DecB64(self, enc_list):
        resultDec = ''
        dec = create_string_buffer(self.bufSize*2)
        decLen = c_int()
        for target in enc_list:
            enc = create_string_buffer(bytes(target, "utf8"))
            ret = self.clib.SCP_DecB64(self.iniFilePath.encode(), b'KEY1', enc, len(enc.value), dec, byref(decLen), sizeof(dec))
            if ret != 0 :
                print("WSCP_DecB64 error :", ret)
                return ret, resultDec
            resultDec += dec.value.decode('utf-8')
        return ret, resultDec