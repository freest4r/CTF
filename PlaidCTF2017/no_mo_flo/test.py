import subprocess
import os, sys
import re

"""you can solve following problems with this plugin:
https://github.com/angr/angr-doc/tree/master/examples/defcamp_r100
"""

def print_array(prefix, arr):
    buf = []
    for x in arr:
        buf.append(x)
    print prefix + " = " + ', '.join(buf)

def cleansing(text):
    text = re.sub("^\.", "", text, flags=re.MULTILINE)
    text = re.sub("^\.*\n", "", text, flags=re.MULTILINE)
    text = re.sub("^\s*\n", "", text, flags=re.MULTILINE)
    return text

#FINDS = ["0x4027f1"]
FINDS = ["0x400EFB"]
AVOIDS = ["0x4027f8"]

INPUT_LENGTH = "32"

BUF_INIT_CODE = r"""
initial_state.libc.buf_symbolic_bytes = INPUT_LENGTH + 1
initial_state.posix.files[0].seek(0)
for i in range(INPUT_LENGTH): # initialize all array items
    k = initial_state.posix.files[0].read_from(1)
    initial_state.add_constraints(k != '\x00') # null
    # initial_state.add_constraints(k >= ' ') # '\x20'
    # initial_state.add_constraints(k <= '~') # '\x7e'
initial_state.posix.files[0].seek(0)
"""

FLAG_PREFIX = "PCTF{"
FLAG_PREFIX_CODE = ""
if not FLAG_PREFIX == None:
    print("[*] flag prefix = " + FLAG_PREFIX)
    for i in range(len(FLAG_PREFIX)):
        FLAG_PREFIX_CODE += "k = initial_state.posix.files[0].read_from(1)\ninitial_state.se.add(k == ord('%s'))\n" % (FLAG_PREFIX[i])
    FLAG_PREFIX_CODE += "initial_state.posix.files[0].seek(0)\n"

source_code = r"""
import angr
import sys, threading
FLAG_FINISHED = False
def cyclic_task():
    # NOTE: enable SIGINT while this child process is runnig 
    # (stdX.read() in PIPE.communicate() may blocks asynchronous SIGINT)
    sys.stdout.write('.') 
    sys.stdout.flush()
    if FLAG_FINISHED == False:
        threading.Timer(1, cyclic_task).start()
BIN = "no_flo"
p = angr.Project(BIN, load_options={"auto_load_libs": False})
initial_state = p.factory.entry_state(args=[BIN])
BUF_INIT_CODE
FLAG_PREFIX_CODE
initial_path = p.factory.path(initial_state)
pg = p.factory.path_group(initial_state)
print("[*] angr exploring...")
cyclic_task()
pg.explore(find=FINDS, avoid=AVOIDS)
FLAG_FINISHED = True
print("")
if len(pg.found):
    found = pg.found[0]
    print("[*] found: stdin = %r" % found.state.posix.dumps(0).strip('\0\n'))
else:
    print("[!] not found")
"""

#source_code = source_code.replace("__BIN__", BIN)
source_code = source_code.replace("FLAG_PREFIX_CODE", FLAG_PREFIX_CODE)
source_code = source_code.replace("BUF_INIT_CODE", BUF_INIT_CODE)
source_code = source_code.replace("INPUT_LENGTH", INPUT_LENGTH)
source_code = source_code.replace("FINDS", "(" + ','.join([str(x) for x in FINDS]) + ")")
source_code = source_code.replace("AVOIDS", "(" + ','.join([str(x) for x in AVOIDS]) + ")")

open("angr-solve.py", "w").write(source_code)
