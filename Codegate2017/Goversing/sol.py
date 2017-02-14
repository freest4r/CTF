#!/usr/bin/python
import angr
 
def main():
    p = angr.Project('Goversing')
 
    #main           = 0x4007c2  # Address of main
    #main           = 0x402277  # Address of main
    main           = 0x402210  # Address of main
    win            = 0x40275d  # good
    #fail           = 0x400803  # fail
    find           = (win,)
    avoid = (0x402285,0x402541,0x40246f,)
    #avoid          = (0x404f97,0x404f68,0x404f30,0x404f0b,)
 
    init = p.factory.blank_state(addr=main)
    pgp = p.factory.path_group(init)
 
    # Now stuff becomes interesting
    ex = pgp.explore(find=find, avoid=avoid)
 
    print(ex)
    print ex.found[0].state.posix.dumps(0)
    print ex.found[0].state.posix.dumps(1)
    #flag = s.se.any_str(s.memory.load(flag_addr, 50))

 
if __name__ in '__main__':
    print(main())
