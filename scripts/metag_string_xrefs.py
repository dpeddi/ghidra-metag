# Create string / rodata cross-references in a metag core loaded at base 0.
# @category metag
# @menupath Tools.Metag.Apply rodata xrefs
#
# The firmware scatter-loads rodata into SEVERAL RAM segments, each with its own
# base: VA = file_offset + DELTA. Code builds pointers 0xB0xxxxxx (MOVT+ADD) that
# are not mapped in the base-0 image, so Ghidra makes no reference. For every
# reconstructed pointer (dataxrefs.csv) we try each known segment DELTA and, when
# VA-DELTA lands on a real string start inside the image, add the reference there.
# Pointers into code / RAM data use other bases and match no window -> skipped.
#
# Run after import + auto-analysis; at the prompt pick unpack/analysis/<core>/dataxrefs.csv.
# DELTAS below are for 0286_core (recover others with unpack/analysis/find_rodata_base.py).
import csv
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.data import TerminatedStringDataType

DELTAS = [0xB007BB24, 0xB0816B38, 0xB00CAB94, 0xB031CABC, 0xB07E9028, 0xB07AE9B4]   # 0286_core rodata segments

mem = currentProgram.getMemory()
lo = mem.getMinAddress().getOffset(); hi = mem.getMaxAddress().getOffset()
refmgr = currentProgram.getReferenceManager()

def str_start(off):
    # off is a file offset == address; true if a NUL-terminated printable string starts here
    try:
        if off <= lo: return False
        if (getByte(toAddr(off-1)) & 0xff) != 0: return False
        b = getByte(toAddr(off)) & 0xff
        return 32 <= b < 127
    except: return False

f = askFile("Select dataxrefs.csv", "Open")
made = 0; strung = 0; skip = 0
for row in csv.DictReader(open(f.getAbsolutePath())):
    try:
        co = int(row['code_offset'], 16); va = int(row['target_addr'], 16)
    except: continue
    hit = None
    for D in DELTAS:
        fo = va - D
        if lo <= fo <= hi and str_start(fo): hit = fo; break
    if hit is None: skip += 1; continue
    frm = toAddr(co); to = toAddr(hit)
    try: refmgr.addMemoryReference(frm, to, RefType.DATA, SourceType.USER_DEFINED, 0); made += 1
    except: continue
    if getDataAt(to) is None:
        try: createData(to, TerminatedStringDataType()); strung += 1
        except: pass

println("rodata xrefs created: %d | strings defined: %d | no-window skipped: %d" % (made, strung, skip))
