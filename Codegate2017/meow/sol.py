#!/usr/bin/python
import angr
 
def main():
    p = angr.Project('meow')
 
    #main           = 0x555555555641 # Address of main
    main           = 0x5555555554f9 # Address of main
    find           = (0x55555555568b,)
    #find           = (0x55555555566f,)
    #find           = (0x5555555556c4,)
    avoid          = (0x555555555659,)
 
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
