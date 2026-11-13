# Name metag functions from our fingerprints + string references + call-graph hubs.
# @category metag
# @menupath Tools.Metag.Name functions
#
# Run in Ghidra (Script Manager) after importing 0286_core.bin with the metag
# language and running Auto-Analysis. When prompted, select
#   unpack/analysis/0286/fingerprints.csv
# Addresses in the CSV are file offsets == Ghidra addresses (image loaded at base 0).
import csv, re
from ghidra.program.model.symbol import SourceType

PREFIX = {
 'memcpy_like':'copy', 'memset_like':'fill', 'copy_loop':'cpyloop',
 'scan_loop':'scan',  'lock_critical':'lock', 'jump_table':'jtbl',
}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

def has_string(d):
    try:
        if d is None: return None
        v = d.getValue()
        if v is None: return None
        s = unicode(v)
        # printable, reasonable length
        if len(s) >= 3 and sum(1 for c in s if 32 <= ord(c) < 127) >= len(s)*0.8:
            return s
    except: pass
    return None

def sanitize(s):
    s = re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_')
    return s[:28] if s else None

# ---------- pass 1: fingerprints ----------
n1 = 0
try:
    f = askFile("Select fingerprints.csv", "Open")
    for row in csv.reader(open(f.getAbsolutePath())):
        if not row or row[0] == 'offset': continue
        try: off = int(row[0], 16)
        except: continue
        tag = row[2] if len(row) > 2 else ''
        addr = toAddr(off)
        func = getFunctionAt(addr)
        if func is None:
            try: func = createFunction(addr, None)
            except: func = None
        if func is None: continue
        base = PREFIX.get(tag, tag or 'fn')
        try:
            func.setName("%s_%06x" % (base, off), SourceType.USER_DEFINED)
            n1 += 1
        except: pass
except Exception as e:
    println("fingerprint pass skipped: %s" % e)

# ---------- pass 2: name by referenced string ----------
n2 = 0
try:
    data_it = listing.getDefinedData(True)
    for d in data_it:
        s = has_string(d)
        if not s: continue
        san = sanitize(s)
        if not san: continue
        for ref in getReferencesTo(d.getAddress()):
            fn = getFunctionContaining(ref.getFromAddress())
            if fn is not None and fn.getName().startswith("FUN_"):
                try:
                    fn.setName("s_%s_%06x" % (san, fn.getEntryPoint().getOffset()),
                               SourceType.USER_DEFINED)
                    n2 += 1
                except: pass
except Exception as e:
    println("string pass skipped: %s" % e)

# ---------- pass 3: mark heavily-called hubs still unnamed ----------
n3 = 0
try:
    funcs = list(fm.getFunctions(True))
    deg = []
    for fn in funcs:
        try: deg.append((len(getReferencesTo(fn.getEntryPoint())), fn))
        except: pass
    deg.sort(key=lambda x: -x[0])
    for d, fn in deg[:40]:
        if d >= 8 and fn.getName().startswith("FUN_"):
            try:
                fn.setName("hub%03d_%06x" % (d, fn.getEntryPoint().getOffset()),
                           SourceType.USER_DEFINED)
                n3 += 1
            except: pass
except Exception as e:
    println("hub pass skipped: %s" % e)

println("Renamed: %d by fingerprint, %d by string, %d hubs." % (n1, n2, n3))
