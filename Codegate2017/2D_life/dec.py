#!/usr/bin/python
import requests
import base64, itertools
import urllib
from Crypto.Cipher import DES3


#url = "http://110.10.212.147:24135/?p=secret_login"
url = "http://110.10.212.147:24136/?p=secret_login"
part1 = "vpJWft4HuyM="
part2 = "ChJ+6ms5rDWNAxrXrD3i/xQlCXqfXmYv+Sb/nRCGf4aYl+VgM4V5w+4X8gIgjk/BzsnPJ4s+w0h9CP4xmWwM+Q=="

IV = base64.b64decode(part1)
encrypted_txt = base64.b64decode(part2)

print IV.encode("hex")
print encrypted_txt.encode("hex")

'''

if __name__=="__main__":
    #charset='0123456789'
    charset='abcdefghijklmnopqrstuvwxyz'
    charset=""
    #IV = "\x00"*8 + IV
    for i in range(0, 255):
        charset+=chr(i)
    print charset.encode("hex")
    for key_ in itertools.product(charset, repeat=16):
        key = ''.join(key_)
        print key.encode("hex")
        des3 = DES3.new(key, DES3.MODE_CBC, IV)
        dec = des3.decrypt(encrypted_txt)
        print dec
        dec2_=[]
        for i in range(0, 16):
            dec2_.append(ord(IV[i]) ^ ord(dec[i]))
        dec2=''.join(dec2_)
        print dec2
        
        
'''
