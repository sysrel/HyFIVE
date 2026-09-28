import sys
from addr2FuncMap import readSymbols, getFunction

def recordTaintPropagation(taintmap):
    while True:
            line = sys.stdin.readline().strip()
            if len(line) == 0:
               break   
            ls = line.split(' ')
            if len(ls) >= 3:
               if not ls[0] in taintmap.keys():
                  taintmap[ls[0]] = set()
               taintmap[ls[0]].add((ls[1], ls[2]))
               #print(f"Recording {ls[0]} {ls[1]} {ls[2]} {ls[0] in taintmap.keys()}")

def explainTaint(taintmap, fmap, faddrs, addr, pc=None, depth=0, visited=None):
    if visited == None:
       visited = set()
    #print(f"Explaining taint for {addr} size of taint map {len(taintmap)}")
    if not addr in taintmap.keys():
       return
    if addr in visited:
       return 
    visited.add(addr)
    res = ""
    for t in taintmap[addr]:
        if not pc == None and depth == 0 and not pc == t[1]:
           continue
        v = set()
        for ve in visited:
            v.add(ve) 
        explainTaint(taintmap, fmap, faddrs, t[0], pc, depth + 1, v)
        del v
        fn = getFunction(fmap, faddrs, int(t[1], 16))
        s = "{} <- {} @ {}[{}]\n".format(addr, t[0], t[1], fn)
        print(f"{s}")

def filterForPC(taintmap, pc, target_list):
    for key in taintmap.keys():
        for addr, pca in taintmap[key]:
            if pca == pc:
               target_list.append(key)


def filterForFunctionName(taintmap, fmap, faddrs, fname, target_list):
    if not any([f for k, f in fmap.items() if f == fname]):
       print(f"Error: unknown function {fname}")
       return        
    for key in taintmap.keys():
        for addr, pca in taintmap[key]:
            fn = getFunction(fmap, faddrs, int(pca, 16))
            if fn == fname:
               target_list.append(key)

def filterForFunctionAddr(taintmap, fmap, faddrs, faddr, target_list):
    if faddr in fmap.keys():
       filterForFunctionName(taintmap, fmap, faddrs, fmap[faddr], target_list)
    else:
       print(f"Error: unknown function address {faddr}")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
       fmap = {}
       faddrs = []
       visitedmap = {}
       taintmap = {} 
       out, err, code = readSymbols(sys.argv[1], fmap, faddrs)
       if len(sys.argv) >= 3:
          recordTaintPropagation(taintmap)
          target = sys.argv[2]
          tl = []
          if "pc:" in target:
             ts = target.split('pc:')
             if len(ts) >= 2:
                filterForPC(taintmap, ts[1], tl)
          if "addr:" in target:
             ts = target.split('addr:')
             if len(ts) >= 2:
                tl.append(ts[1])
          if "fname:" in target:
             ts = target.split('fname:')
             if len(ts) >= 2:
                filterForFunctionName(taintmap, fmap, faddrs, ts[1], tl)
          if "faddr:" in target:
             ts = target.split('faddr:')
             if len(ts) >= 2:
                filterForFunctionAddr(taintmap, fmap, faddrs, int(ts[1], 16), tl)
          for t in tl: 
              print(f"Target address: {t}")
              explainTaint(taintmap, fmap, faddrs, t, None)
