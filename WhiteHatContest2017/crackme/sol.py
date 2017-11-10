import angr

proj = angr.Project('./crackme', load_options={'auto_load_libs': False})
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: "CONGRATZ" in s.posix.dumps(1))
s=simgr.found[0]
print s.posix.dumps(1)
print s.posix.dumps(0)

