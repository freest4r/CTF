#!/usr/bin/python
from subprocess import *
import angr
FNAME = "prob4"
def objdump(fname):
    p = Popen(["objdump","-d", fname],stdout=PIPE)
    data = p.communicate()[0].split("\n")

    for d in data:
        if "callq" in d and "<puts@plt>" in d:
            addr = d[:d.find(":")].strip()
            print addr
            return int(addr,16)

FNAME_init = "prob"
for i in range(1,102):
    FNAME = FNAME_init+str(i)
    print 'solving', FNAME
    find_addr = objdump(FNAME)
    project = angr.Project(FNAME, load_options={"auto_load_libs": False})
    argv1 = angr.claripy.BVS("argv1",100*8)
    initial_state = project.factory.path(args=[FNAME,argv1])
 
    pg = project.factory.path_group(initial_state)
 
    pg.explore(find=find_addr)


    found = pg.found[0]
    solution = found.state.se.any_str(argv1)
 
    solution = solution[:solution.find("\x00")]
    print solution
 
