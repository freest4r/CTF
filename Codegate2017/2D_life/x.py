import base64
import urllib 
import requests


cookie="CBBdC73gY6M%3D%7CwDMJdUTdf2RpbamwqKh5F8YRYbs0VMauEZWn%2BM%2B2aS2DqptFRQP1SlBU0o%2Bu1mjeQ%2Fcy658liVgfy9oL%2BE0pKg%3D%3D"
#### first of nonce equal
#cookie="CIXMxd01+4k=|MrIprFpCycflXQhBFoxCZ39ChtrytawvZcOlaM1MLAPppmmiW9JxVfj2ubg1GInFDnD4MM3tktl76ZWdNoHEvg=="
#### first of p is equal
#cookie="OFT56Cnqpfw=|ibZIrKom0+v7ijpeaXa6xUSAPqWrogR3MrTCVO1geIqxzFTzHD1jFCIeUGiLkyUmptT1iR3aib3PpfFsRm6AgQ=="
#cookie="ySvtu9WNKEo=|d7nqWF16ZjpJ0FFdB4ECWziCQIGj6SupDODRXzIBVGKQvLtNxYjVcL9Ei4PCDOs+MGJuGK4HiTHx3r0Y5MzzIw=="

#### last of p is equal as key
# -1 
#cookie="Y41q1q27cbA=|KmgxKSE+2/0zgXVs3jZld0s/6qcqS/dy5iovtrluM8HqEi33iSKof2g65qFDNQmWaRqebjnaRExSxOfZplOTKg=="
# -3 equal
cookie="dBvRODmXxW4=|w9UVOgogm0miRjSambiKf7OIbeI2ed1BTTjwkAHLUiy8Pfrw3vjq0sRLvQNFjgoFcIttD/IfduqpEYNRyU2agg=="


cookie = urllib.unquote(cookie)

a,b, =  cookie.split("|")

xf = lambda x, y: chr(ord(x) ^ ord(y))
pf = lambda x, y: chr((ord(x) + ord(y))%256)
mf = lambda x, y: chr((ord(x) - ord(y)+256)%256)
af = lambda x, y: chr(ord(x) & ord(y))
xxf = lambda x, y: chr((ord(x) * ord(y))%256)
xxf = lambda x, y: chr((ord(x) % ord(y))%256)



def send(n, p, keyword):
	n = base64.b64encode(n)
	p = base64.b64encode(p)
	headers = { 'Cookie': 'identify='+ urllib.quote(n + '|' + p) }
	r = requests.get('http://110.10.212.135:24135/?p=secret_login', headers=headers)
	return (r.text, r.text.find(keyword) > -1)


def applykey(p, key, f=xf):
        d = ""
        for i,x in enumerate(p):
                y = key[i%len(key)]
	        d += f(x, y)
        return d


nonce = base64.b64decode(a)
p = base64.b64decode(b)  # 64 length


def test(n,p, testKeyword):
	t, b = send(n, p, testKeyword)
	AFTER = '>Hello, '
	s = t.find(AFTER)
	print t
	return b

newnonce = nonce


iv = '\x45\x55\x0e\x58\xfc\xa7\x26\x83' #[MESSAGE ]
p0 = '86614638648e2f3d'.decode('hex')   # FROM SPY
p0 = '86614638648e2f3d'.decode('hex')   # FROM SPY
p0 = '86614638648e2f3d'.decode('hex')   # FROM SPY
p0 = '86614638648e2f3d'.decode('hex')   # FROM SPY
p0 = '86614638648e2f3d'.decode('hex')   # FROM SPY
p0 = '86614638648e2f3d'.decode('hex')   # FROM SPY
p6 = '10a76bd0a9138b5a'.decode('hex')   # SPY;66

p24 = ''.decode('hex')   # SPY;66









m =    'FROM SPY<!--TABLE:agents NUMBER OF COLUMNS:5--> SPY;66'
print len(m)
k = applykey(p, m)

word = 'FROM SPY<!--                                --> SPY;66'
word = 'FROM agents <!--TABLE:a                     --> SPY;66'# gentsMBE' #R OF COLUMNS:5--> SPY;66'
word = 'FROM SPY<!--TABLE:agents NUMBER OF COLUMNS:1--> aPY;01'
aa = applykey(word, k)
print len(aa+p[54:])

test(nonce, aa + p[54:], '')
quit()


n = 16
#print applykey(p24, p[n:n+8])
#quit()
iv = ''
for x in range(0, 8):
	l = 7 - len(iv)
	z = '\x00' * l

	for id in range(0, 256):
		print hex(id),
		vvv = z + applykey(chr(id)+iv, chr(len(iv)+1))


		print vvv.encode('hex'), len(p[0:n]+vvv), iv.encode('hex')
		#print (p[0:n]+vvv).encode('hex')

		if not test(nonce, p[0:n]+vvv, 'decryp'):
			print hex(id)
			iv = chr(id) + iv
			break

print iv.encode('hex')
print applykey(iv, p[n:n+8])

quit()
































