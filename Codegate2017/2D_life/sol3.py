#!/usr/bin/python
import requests
import base64
import urllib
import os

#COOK = "vpJWft4HuyM%3D%7CChJ%2B6ms5rDWNAxrXrD3i%2FxQlCXqfXmYv%2BSb%2FnRCGf4aYl%2BVgM4V5w%2B4X8gIgjk%2FBzsnPJ4s%2Bw0h9CP4xmWwM%2BQ%3D%3D"

#url = "http://110.10.212.147:24135/?p=secret_login"
url = "http://110.10.212.147:24136/?p=secret_login"
part1 = "vpJWft4HuyM="
part2 = "ChJ+6ms5rDWNAxrXrD3i/xQlCXqfXmYv+Sb/nRCGf4aYl+VgM4V5w+4X8gIgjk/BzsnPJ4s+w0h9CP4xmWwM+Q=="

def change(string, idx, value):
    return string[:idx] + chr(value) + string[idx+1:]


#
decode_part1 = base64.b64decode(part1)
decode_part2 = base64.b64decode(part2)

print decode_part1.encode("hex"), len(decode_part1)
print decode_part2.encode("hex"), len(decode_part2)
print "===="


iv = "\xc8\xec\x3e\x16\xa4\x7b\xc5\x38"
intermed=[]
for i in range(0,8):
    #intermed.append( hex(ord(iv[i])^0x8 ) )
    print chr((ord(iv[i])^0x8)^ord(decode_part1[i]))
#print ''.join(intermed)
os.sys.exit(1)

decode_part1="\00"*8
for i in range(0, 8):
    for v in range(0,256):
        new_part1 = change(decode_part1, i, v)
        #new_part2 = change(decode_part2, j, k)

        part1= base64.b64encode(new_part1)
        #part1= base64.b64encode(decode_part1)
        #part2= base64.b64encode(new_part2)
        part2= base64.b64encode(decode_part2)


        COOK = urllib.quote(part1 + "|" + part2[:8])
        cookie = {'identify': COOK}
        data = requests.get(url, cookies= cookie).text
        if 'decrypt' not in data:
        #if "TABLE:agents" in data:
        #if "Hello, SPY" not in data:
            print new_part1.encode("hex")
            data = data[data.find("<title>"):]
            print i, hex(v)
            print data
            decode_part1=new_part1
            #break
    break
