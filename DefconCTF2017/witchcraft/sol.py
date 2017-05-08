from subprocess import *
import re, ctypes, base64
from pwn import *

def get_function_list(data):
    data2 = data[data.find("401540:"):]
    func1 = data2[data2.find("callq  ")+7:data2.find(" <")]
    data3 = data[data.find(func1+":"):]
    data3 = data3[:data3.find("retq")]
    fct=[]
    for m in re.finditer("movzbl(.*?)callq(.*?)(\w+)(.*?)<", data3, re.DOTALL):
        fct.append(m.group(3))
    return fct

def solve(fn, data):
    data = data[data.find(fn+":"):]
    data = data[:data.find("retq"):]
    if 'cmp' in data:
        target = re.search("cmp(.*?)\$0x(.*?),", data, re.DOTALL).group(2)
    else:
        target = '0'

    target = ctypes.c_int64(int(target,16)).value
    data = data.split("\n")
    data = data[::-1]
    for d in data:
        if 'add ' in d:
            n = int(re.search("add(.*?)\$0x(.*?),", d, re.DOTALL).group(2),16)
            target -= n
        elif 'sub' in d:
            n = int(re.search("sub(.*?)\$0x(.*?),", d, re.DOTALL).group(2),16)
            target += n
    return chr(target)
if __name__=="__main__":
    answers={}
    flist = open("flist").read()[:-1].split("\n")
    for fname in flist:
        p = Popen(["objdump","-d", fname],stdout=PIPE)
        data = p.communicate()[0]
        fct = get_function_list(data)
        ans=''
        for fn in fct:
            ans+=solve(fn, data)
        answers[fname]=base64.b64encode(ans)

    p = remote("cm2k-witchcraft_5f60e994e19a100de1dee736608d639f.quals.shallweplayaga.me", 12003)
    print p.recvline()
    while True:
        fname = p.recvline()[:-1]
        if 'flag' in fname:
            print fname
            break
        p.sendline(answers[fname])
    p.close()
