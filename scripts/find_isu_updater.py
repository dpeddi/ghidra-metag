# READ-ONLY: map scatter seg at its VA, decompile candidates, surface ISU-updater C.
# @category metag
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import jarray

mem=currentProgram.getMemory()
af=currentProgram.getAddressFactory().getDefaultAddressSpace()
# map the TWO big rodata scatter segments so the decompiler can read strings:
#   0xa00: file 0xb166c len 0x1e96c4 -> VA 0xb012d190 (ISU strings, DAB/FSB, __FILE__)
#   0xa40: file 0x29d4dc len 0x8b000 -> VA 0xb0319000 (mDNS)
for name,ffile,va,ln in [("a00",0xb166c,0xb012d190,0x1e96c4),("a40",0x29d4dc,0xb0319000,0x8b000)]:
    try:
        src=jarray.zeros(ln,'b'); mem.getBytes(af.getAddress(ffile),src)
        mem.createInitializedBlock("sc_"+name, af.getAddress(va), ln, (0), None, False)
        mem.setBytes(af.getAddress(va), src); println("mapped %s @ %x"%(name,va))
    except Exception as e: println("map %s failed: %s"%(name,e))

fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
cand=set()
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    if ins.getMnemonicString()!="MOVT": continue
    for i in range(ins.getNumOperands()):
        for o in ins.getOpObjects(i):
            try:
                if (o.getValue()&0xffff) in (0xb02a,0xb02b):
                    f=fm.getFunctionContaining(ins.getAddress())
                    if f: cand.add(f)
            except: pass
println("candidates (MOVT 0xb02a/b): %d"%len(cand))
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
KEYS=("ISU:","MD5","md5","check out","Sizes do not","Bad MD5","CompSize","DecompSize","FSH","Decomp")
found=[]
for f in cand:
    r=dec.decompileFunction(f,90,mon)
    if not (r and r.decompileCompleted()): continue
    c=r.getDecompiledFunction().getC()
    if any(k in c for k in KEYS):
        found.append((f.getEntryPoint().getOffset(),c))
println("functions whose C contains ISU/MD5 strings: %d"%len(found))
for off,c in sorted(found):
    println("\n################ FUN_%06x ################"%off)
    println(c)
