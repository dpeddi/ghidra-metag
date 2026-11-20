# READ-ONLY: collect addresses where SLEIGH failed (bad-instruction bookmarks + undefined in funcs).
# @category metag
OUT="/sessions/rcw-01x2jnmdnwx2yvkfqsf9a7x3/bad_instr.txt"
bm=currentProgram.getBookmarkManager()
mem=currentProgram.getMemory()
rows=[]
it=bm.getBookmarksIterator("Error")
while it.hasNext():
    b=it.next()
    a=b.getAddress()
    try:
        w=mem.getInt(a) & 0xffffffff
    except: w=0
    rows.append((a.getOffset(), w, b.getCategory(), b.getComment()))
# also scan function bodies for addresses with no instruction (holes)
println("Error bookmarks: %d"%len(rows))
from collections import Counter
# write all
with open(OUT,"w") as f:
    for off,w,cat,com in sorted(rows):
        f.write("%08x %08x %s | %s\n"%(off,w,cat,com))
println("wrote %s"%OUT)
# summarize by top byte / opcode nibble of the failing word
c=Counter((w>>24)&0xff for off,w,_,_ in rows if w)
println("top failing high-byte: %s"%c.most_common(12))
