# READ-ONLY: export all functions (offset,size_bytes,user_named,name) to CSV.
# @category metag
import csv
OUT="/sessions/rcw-01x2jnmdnwx2yvkfqsf9a7x3/funcs_export.csv"
fm=currentProgram.getFunctionManager()
rows=[]
for f in fm.getFunctions(True):
    ep=f.getEntryPoint()
    off=ep.getOffset()
    body=f.getBody()
    size=body.getNumAddresses()
    nm=f.getName()
    src=f.getSymbol().getSource().toString() if f.getSymbol() else ""
    user=1 if src=="USER_DEFINED" else 0
    rows.append((off,size,user,nm))
rows.sort()
with open(OUT,"w") as fp:
    w=csv.writer(fp); w.writerow(["offset","size_bytes","user_named","name"])
    for off,size,user,nm in rows:
        w.writerow(["0x%06X"%off,size,user,nm])
println("exported %d functions to %s"%(len(rows),OUT))
# quick stats
named=sum(1 for r in rows if not r[3].startswith(("FUN_","fun_")))
println("non-FUN_ named: %d"%named)
