from pwn import *
#import pdb
exe = context.binary = ELF('math_game')
remotehost = ('ctf.fibonhack.it', 10006)

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
        
#context.log_level = 'debug'
io = start()
io.recvuntil(b"name?\n", drop=True)
io.sendline(b"Outis")
io.recvuntil(b"math?\n", drop=True)
score = 0
while(True):
	init = io.recvline().decode("utf-8")
	#log.info(f"inizia: {init}")
	if init == "\n":
		break
	res = init[init.rfind("s ")+2:]
	#log.info(f"pulito: {res}")
	numbers = res.strip(" ?\n").split(" + ")
	tot = 0
	if(score != "42"):
		for numb in numbers:
		      tot += int(numb)
	      
	#pdb.set_trace()
	io.sendline(str(tot).encode())
	io.recvuntil(b'now ', drop=True)
	score = io.recvline().decode("utf-8").strip("\n")
	#log.info(f"score: {score}")
	
# ui.pause()

io.interactive()