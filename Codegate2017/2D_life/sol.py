#!/usr/bin/python
import requests
import base64
import urllib

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


candidate = [ (0,172), (0,200), (0,212), (1,136), (1,236), (1,240), (2,34), (2,62), (2,90), (3,10), (3,22), (3,114), (4,164), (4,184), (4,192), (5,31), (5,103), (6,161), (6,197), (6,217), (7,36), (7,56), (7,92)]

for i in range(0, len(candidate)):
    new_part1 = change(decode_part1, candidate[i][0], candidate[i][1])
    for j in range(0, len(decode_part2)):
        for k in range(0, 255):
            new_part2 = change(decode_part2, j, k)

            part1= base64.b64encode(new_part1)
            #part1= base64.b64encode(decode_part1)
            part2= base64.b64encode(new_part2)
            #part2= base64.b64encode(decode_part2)


            COOK = urllib.quote(part1 + "|" + part2)
            cookie = {'identify': COOK}
            #print cookie
            data = requests.get(url, cookies= cookie).text
            if "Is that all?" in data:
                continue
            data = data[data.find("<title>"):]
            if 'Hello, SPY' not in data or "Rank :66" not in data:
                print candidate[i][0], candidate[i][1], j, k
                print data.encode("utf-8")
                #data2= data[data.find(">"):data.find("<br>")]
                #print data2.encode("hex")


            '''
            i=0
            j=0
            result =''
            while j<=len(decode_part2)-1:
                #print i,j, "%02x" % (ord(decode_part1[i]) ^ ord(decode_part2[j]))
                result += "%02x" % (ord(decode_part1[i]) ^ ord(decode_part2[j]))
                i+=1
                j+=1
                if i == len(decode_part1[i]):
                    i = 0
            print result
            '''
