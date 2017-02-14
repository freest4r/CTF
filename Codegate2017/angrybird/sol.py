#!/usr/bin/python
import angr
 
p = angr.Project('angrybird')

#main           = 0x4007c2 
main           = 0x4007da
find            = 0x404fc1  # good
avoid          = (0x404f97,0x404f68,0x404f30,0x404f0b,0x404ee2, 0x404eb9, 0x404e90, 0x404e61, 0x404e3c, 0x404e13, 0x404dea, 0x404dc1, 0x404d98, 0x404d6f, 0x404d39, 0x404d10, 0x404ce7, 0x404cbe, 0x404c95, 0x404c6c, 0x404c29, 0x404c00, 0x404bd7,)

init = p.factory.blank_state(addr=main)
pgp = p.factory.path_group(init)

ex = pgp.explore(find=find, avoid=avoid)

print ex.found[0].state.posix.dumps(1)
