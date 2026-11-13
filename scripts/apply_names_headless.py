# Headless: apply names from a CSV passed as arg0 (offset,name,evidence).
# @category metag
import csv
from ghidra.program.model.symbol import SourceType
args = getScriptArgs()
path = args[0]
rows = list(csv.DictReader(open(path)))
ren = made = skip = 0
for row in rows:
    o = row.get('offset'); nm = row.get('name')
    if not o or not nm: continue
    try: a = toAddr(int(o, 16))
    except: continue
    fn = getFunctionAt(a)
    if fn is None:
        if getInstructionAt(a) is None:
            try: disassemble(a)
            except: pass
        try: fn = createFunction(a, None)
        except: fn = None
        if fn is not None: made += 1
    if fn is None: skip += 1; continue
    try: fn.setName(nm, SourceType.USER_DEFINED); ren += 1
    except:
        try: fn.setName(nm + '_' + o[2:], SourceType.USER_DEFINED); ren += 1
        except: skip += 1
println("METAG-APPLY named %d functions (%d newly created), skipped %d" % (ren, made, skip))
