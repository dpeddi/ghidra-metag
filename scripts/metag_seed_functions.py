# Seed functions at every entry we found by linear analysis, so Ghidra
# disassembles and decompiles the regions its recursive-descent auto-analysis
# never reached.
# @category metag
# @menupath Tools.Metag.Seed functions from CSV
#
# WHY: Ghidra follows only provable flow from a few seeds and cannot follow
# metag computed jumps (JUMP tables), so large valid-code regions stay as raw
# bytes. Our objdump linear sweep + CALLR/return entry detection already located
# ~26k function starts (unpack/analysis/<core>/functions.csv). This creates a
# function at each, which triggers disassembly + decompilation there.
#
# Run after import + initial auto-analysis. At the prompt pick
#   unpack/analysis/0286/functions.csv   (columns: offset,callers,size_ins,fingerprint)
# Offsets are file offsets == Ghidra addresses (image base 0). Safe to re-run.
import csv
f = askFile("Select functions.csv", "Open")
rows = list(csv.DictReader(open(f.getAbsolutePath())))
monitor.initialize(len(rows))
dis = 0; made = 0; already = 0; bad = 0
for row in rows:
    if monitor.isCancelled(): break
    monitor.incrementProgress(1)
    o = row.get('offset') or row.get('addr')
    if not o: continue
    try: addr = toAddr(int(o, 16))
    except: continue
    if getFunctionAt(addr) is not None:
        already += 1; continue
    if getInstructionAt(addr) is None:
        try:
            if disassemble(addr): dis += 1
            else: bad += 1; continue
        except: bad += 1; continue
    try:
        if createFunction(addr, None) is not None: made += 1
    except: pass
println("seeds disassembled: %d | functions created: %d | already defined: %d | undecodable: %d"
        % (dis, made, already, bad))
println("Tip: re-run Auto Analysis (Analysis > One Shot > Decompiler Parameter ID) "
        "then name_metag.py and metag_string_xrefs.py.")
