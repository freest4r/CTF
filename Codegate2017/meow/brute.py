#!/usr/bin/python
import md5
import itertools

#7d30b3a69ce592d9
#0xf955da2fc4809ce0 -> aaaaaaaaaa
#0x618f652224a9469f


if __name__=="__main__":
    #charset='0123456789'
    charset='abcdefghijklmnopqrstuvwxyz'
    for try_ in itertools.product(charset, repeat=10):
        candi = ''.join(try_)
        #print candi, md5.new(candi).hexdigest()[:16]
        if md5.new(candi).hexdigest()[:16] == "9f46a92422658f61":
        #if md5.new(candi).hexdigest()[:16] == "da9c4cf542c40d36":
            print "FIND!", candi
            break
