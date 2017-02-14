import angr
FNAME = "prob3" 
def main():
    project = angr.Project(FNAME, load_options={"auto_load_libs": False})
    argv1 = angr.claripy.BVS("argv1",100*8)
    initial_state = project.factory.path(args=[FNAME,argv1])
 
    pg = project.factory.path_group(initial_state)
 
    pg.explore(find=0x40102f)
    found = pg.found[0]
    solution = found.state.se.any_str(argv1)
 
    solution = solution[:solution.find("\x00")]
    return solution
 
if __name__ == '__main__':
    print(repr(main()))
