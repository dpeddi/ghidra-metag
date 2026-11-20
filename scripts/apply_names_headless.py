import csv
from ghidra.program.model.symbol import SourceType

print("=== Jython Apply Names Starting ===")
path = 'unpack/analysis/0286/names.csv'
reader = csv.DictReader(open(path))
ren = 0
made = 0
skip = 0
for row in reader:
    o = row.get('offset')
    nm = row.get('name')
    if not o or not nm:
        continue
    try:
        a = toAddr(int(o, 16))
    except:
        continue
    fn = getFunctionAt(a)
    if fn is None:
        if getInstructionAt(a) is None:
            try:
                disassemble(a)
            except:
                pass
        try:
            fn = createFunction(a, None)
        except:
            fn = None
        if fn is not None:
            made += 1
    if fn is None:
        skip += 1
        continue
    try:
        fn.setName(nm, SourceType.USER_DEFINED)
        ren += 1
    except:
        try:
            fn.setName(nm + '_' + o[2:], SourceType.USER_DEFINED)
            ren += 1
        except:
            skip += 1

print('METAG-APPLY named %d functions (%d newly created), skipped %d' % (ren, made, skip))
