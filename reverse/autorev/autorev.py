import angr
import claripy

symbols = [claripy.BVS(f'vat_{i}', 8) for i in range(0x100)]

#	creo il progetto
p = angr.Project('./autorev')

# dopo la gets 0x004079d3  nella variabile z all'indirizzo 0x00613060

start_state = p.factory.blank_state(addr = 0x004079cc)

z_addr = 0x00613060

# inserisco variabili simpolice nella variabile z
for i in range(0x100):
	start_state.memory.store(z_addr + i, symbols[i])

for b in symbols:
	start_state.solver.add(b >= 0x20)
	start_state.solver.add(b <= 0x7e)

smgr = p.factory.simgr(start_state)

smgr.explore(find = 0x00408953, avoid = 0x00408961)

if smgr.found:
	solution_state = smgr.found[0]
	
	flag = ""
	
	for x in symbols:
		a = solution_state.solver.eval(x)
		flag += chr(a)
	print(flag)

