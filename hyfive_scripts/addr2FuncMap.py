import subprocess
import sys


def readSymbols(elffile, fmap, faddrs):

    try:
        # Start the process
        process = subprocess.Popen(
            ["nm", elffile], 
            stdout=subprocess.PIPE,   # Capture standard output
            stderr=subprocess.PIPE,   # Capture standard error
        )

        #print(f"Finished processing...")
        while True:
            line = process.stdout.readline()
            if line:
               dline = line.decode('utf-8', 'replace')
               lst = dline.strip().split(' ')
               #print(f"{dline} {len(lst)}")
               if len(lst) == 3:
                  addr = int(lst[0], 16)
                  fmap[addr] = lst[2]          
                  #print(f"recording {lst[2]} for {hex(addr)}")
                  faddrs.append(addr)
            else:
               break

        faddrs.sort() 
        return stdout, stderr, process.returncode

    except FileNotFoundError:
        return "", f"Command not found: {command[0]}", 127
    except Exception as e:
        return "", f"Error running command: {e}", 1


def getFunction(fmap, faddrs, addr):
    i = 0
    while i < len(faddrs):
        if addr == faddrs[i]:
           break
        if addr < faddrs[i]:
           i -= 1
           break
        i += 1
    if i>=0 and i < len(faddrs):
       if faddrs[i] in fmap.keys():
          return fmap[faddrs[i]]
    return "" 

def recordCovered(visitedmap, f, addr):
    if not f in visitedmap.keys():
       visitedmap[f] = set()
    visitedmap[f].add(addr)

def mapAddrs(fmap, faddrs, visitedmap, afile, max=None):
    i = 0
    if not afile:
       while True:
             if not max == None and i >= max:
                break
             i += 1
             line = sys.stdin.readline().strip()
             if len(line) == 0:
                break
             try: 
                addr = int(line, 16)
                fn = getFunction(fmap, faddrs, addr)
                recordCovered(visitedmap, fn, addr)
                print(f"{line} -> {fn}")
             except:
                print(f"Skipping non-int {line}")
                continue
       return 
    with open(afile, 'r') as afs:
         for line in afs:
             if not max == None and i >= max:
                break
             i += 1 
             try: 
                addr = int(line, 16)
                fn = getFunction(fmap, faddrs, addr)
                recordCovered(visitedmap, fn, addr)
                print(f"{line.strip()} -> {fn}")
             except:
                print(f"Skipping non-int {line.strip()}")
                continue 

def summarize(visitedmap):
    for fn in visitedmap.keys():
        pcs = ""
        for pc in visitedmap[fn]:
            pcs += hex(pc) + " "
        print(f"{fn}: {pcs}")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
       fmap = {}
       faddrs = []
       visitedmap = {}
       out, err, code = readSymbols(sys.argv[1], fmap, faddrs)
       max = None
       if len(sys.argv) >= 4:
          max = int(sys.argv[3]) 
       if len(sys.argv) >= 3:
          mapAddrs(fmap, faddrs, visitedmap, sys.argv[2], max)
       else:
          mapAddrs(fmap, faddrs, visitedmap, None, max)
       summarize(visitedmap)
    #print("Exit Code:", code)
