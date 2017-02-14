import angr
#START = 0x555555555659 
def main():
        proj = angr.Project('meow',  load_options={'auto_load_libs': False})
 
        path_group = proj.factory.path_group()
        path_group.explore(find=0x55555555568b, avoid=0x555555555659)
 
        return path_group.found[0].state.posix.dumps(1)
 
if __name__ == '__main__':
        print(repr(main()))
