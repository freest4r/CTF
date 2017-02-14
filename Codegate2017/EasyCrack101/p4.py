import angr
FNAME = "prob64"
def main():
    project = angr.Project(FNAME, load_options={"auto_load_libs": False})
    argv1 = angr.claripy.BVS("argv1",100*8)
    initial_state = project.factory.path(args=[FNAME,argv1])
 
    pg = project.factory.path_group(initial_state)
 
    #pg.explore(find=0x401089)#59
    #pg.explore(find=0x400faa)#60
    #pg.explore(find=0x401070)#61
    #pg.explore(find=0x400e26)#62
    #pg.explore(find=0x400f78)#63
    pg.explore(find=0x4010b1)#64


    found = pg.found[0]
    solution = found.state.se.any_str(argv1)
 
    solution = solution[:solution.find("\x00")]
    return solution
 
if __name__ == '__main__':
    print(repr(main()))
    #pg.explore(find=0x400c7a)#4
    #pg.explore(find=0x401135)#5
    #pg.explore(find=0x4011f1)#6
    #pg.explore(find=0x400cdd)#7
    #pg.explore(find=0x400c9d)#8
    #pg.explore(find=0x400c11)#9
    #pg.explore(find=0x4011d2)#10
    #pg.explore(find=0x40118d)#11
    #pg.explore(find=0x400ec8)#12
    #pg.explore(find=0x4012ce)#13
    #pg.explore(find=0x400e2f)#14
    #pg.explore(find=0x400cf7)#15
    #pg.explore(find=0x400ff8)#16
    #pg.explore(find=0x400fa8)#18
    #pg.explore(find=0x400db6)#19
    #pg.explore(find=0x400e37)#20
    #pg.explore(find=0x401278)#21
    #pg.explore(find=0x400c63)#22
    #pg.explore(find=0x400e7b)#23
    #pg.explore(find=0x400e4a)#24
    #pg.explore(find=0x400bc3)#25
    #pg.explore(find=0x400fac)#26
    #pg.explore(find=0x400d2f)#27
    #pg.explore(find=0x400dc5)#28
    #pg.explore(find=0x400e16)#29
    #pg.explore(find=0x400ffe)#30
    #pg.explore(find=0x400fee)#31
    #pg.explore(find=0x401177)#32
    #pg.explore(find=0x400cc2)#33
    #pg.explore(find=0x400f4f)#34
    #pg.explore(find=0x400c33)#35
    #pg.explore(find=0x40107e)#36
    #pg.explore(find=0x400dc7)#37
    #pg.explore(find=0x4011a1)#38
    #pg.explore(find=0x4010ea)#39
    #pg.explore(find=0x40128a)#40
    #pg.explore(find=0x400cea)#41
    #pg.explore(find=0x4003ef)#42
    #pg.explore(find=0x400edd)#43
    #pg.explore(find=0x4010dd)#44
    #pg.explore(find=0x401027)#45
    #pg.explore(find=0x400d89)#46
    #pg.explore(find=0x400e38)#47
    #pg.explore(find=0x401072)#48
    #pg.explore(find=0x400f84)#49
    #pg.explore(find=0x400cf3)#50
    #pg.explore(find=0x401138)#51
    #pg.explore(find=0x400ecc)#53
    #pg.explore(find=0x400f8c)#54
    #pg.explore(find=0x40118d)#55
    #pg.explore(find=0x400f0b)#56
    #pg.explore(find=0x400e51)#57
    #pg.explore(find=0x400f0b)#58
