# Export the current program's function inventory to CSV (read-only).
# @category metag
# @menupath Tools.Metag.Export functions CSV
# arg0 = output csv path
import csv
args = getScriptArgs()
out = args[0] if args else "/tmp/ghidra_out/functions_ghidra.csv"
fm = currentProgram.getFunctionManager()
rows = []
for f in fm.getFunctions(True):
    body = f.getBody()
    size = body.getNumAddresses()
    start = f.getEntryPoint().getOffset()
    rows.append((start, size, 1 if f.getSymbol().getSource().toString()=="USER_DEFINED" else 0,
                 f.getName()))
with open(out, "w") as fh:
    w = csv.writer(fh)
    w.writerow(["offset","size_bytes","user_named","name"])
    for r in sorted(rows):
        w.writerow(["0x%x"%r[0], r[1], r[2], r[3]])
total = sum(r[1] for r in rows)
print("METAG-EXPORT functions=%d total_code_bytes=%d -> %s" % (len(rows), total, out))
