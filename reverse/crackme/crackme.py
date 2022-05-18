import angr
import claripy

symbols = [claripy.BVS(f'vat_{i}', 8) for i in range(0x1e)]

#	creo il progetto
proj = angr.Project('./Cr4ckZ33C0d3')

state = proj.factory.entry_state()


input_data = state.posix.stdin.load(0, state.posix.stdin.size)

state.solver.eval(input_data, cast_to=bytes)

smgr = p.factory.simgr(state)

printf_addr = 0x00400ea8

smgr.explore(find = printf_addr, avoid = [0x00400ebf,0x00400e73])

if smgr.found:
	solution_state = smgr.found[0]
	
	flag = ""
	
	for x in input_data:
		a = solution_state.solver.eval(x)
		flag += chr(a)
	print(flag)