# READ-ONLY: find task-entry / main candidates via call graph (roots w/ big subtrees).
# @category metag
from ghidra.util.task import ConsoleTaskMonitor
fm=currentProgram.getFunctionManager()
mon=ConsoleTaskMonitor()
funcs=[f for f in fm.getFunctions(True)]
println("functions: %d"%len(funcs))
# incoming call count per function
callers={}
callees={}
for f in funcs:
    cs=f.getCalledFunctions(mon)
    callees[f]=cs
    for c in cs:
        callers[c]=callers.get(c,0)+1
# roots = 0 callers; rank by reachable subtree size (bounded BFS)
def reach(f, cap=4000):
    seen=set(); stack=[f]
    while stack and len(seen)<cap:
        x=stack.pop()
        for c in callees.get(x,()):
            if c not in seen:
                seen.add(c); stack.append(c)
    return len(seen)
roots=[f for f in funcs if callers.get(f,0)==0 and len(callees.get(f,()))>0]
println("root functions (0 callers, >0 callees): %d"%len(roots))
scored=[]
for f in roots:
    scored.append((reach(f), f.getEntryPoint().getOffset(), f.getName(), len(callees.get(f,()))))
scored.sort(reverse=True)
println("top roots by reachable subtree size:")
for sz,off,nm,outd in scored[:25]:
    println("  reach=%-5d out=%-3d FUN_%06x %s"%(sz,outd,off,nm))
