#!/usr/bin/python
import angr

#FIND_ADDR = 0x4027f1
#FIND_ADDR = 0x400EFB
#AVOID_ADDR = 0x4027fd
FIND_ADDR = (0x402c59)
AVOID_ADDR = (0x400710, 0x40071D, 0x40076d, 0x40077a, 0x4007ca, 0x4007d7,
        0x400ac7,0x400a6f,0x400a09, 0x4009a8, 0x400950,0x400834,0x400894,0x4008f4,0x4009a8,
        0x400a09,0x400a6f, 0x400ac7,0x400b24, 0x400b81,0x400bd9, 0x400c31,0x400c8e,
        0x400ce6,0x400d3e, 0x400d96,0x400df2, 0x400e4a,
        0x400ea0,0x400eeb,0x4027f8)#,0x400fb3,0x4010ba,0x4011bc)
INPUT_LENGTH = 32
INPUT_PREFIX = "PCTF{n0_fl0*_*0*l*k*_*h*h*l*_*0}"

FNAME = "no_flo"

proj = angr.Project(FNAME, load_options={"auto_load_libs":False})

initial_state = proj.factory.entry_state(args=[FNAME])
initial_state.libc.buf_symbolic_bytes = INPUT_LENGTH + 1
initial_state.posix.files[0].seek(0)
for i in range(INPUT_LENGTH): # initialize all array items
    k = initial_state.posix.files[0].read_from(1)
    initial_state.add_constraints(k != '\x00') # null
    # initial_state.add_constraints(k >= ' ') # '\x20'
    # initial_state.add_constraints(k <= '~') # '\x7e'
initial_state.posix.files[0].seek(0)

for i in range(len(INPUT_PREFIX)):
    k = initial_state.posix.files[0].read_from(1)
    if i%2==0:# or i<10:
        initial_state.se.add(k ==ord(INPUT_PREFIX[i]))
    elif i == len(INPUT_PREFIX)-1:
        initial_state.se.add(k ==ord(INPUT_PREFIX[i]))
    #initial_state.add_constraints(k ==ord(INPUT_PREFIX[i]))

initial_state.posix.files[0].seek(0)


initial_path = proj.factory.path(initial_state)
path_group = proj.factory.path_group(initial_state, threads=4)
path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

print path_group.found[0].state.posix.dumps(0)
print path_group.found[0].state.posix.dumps(1)
