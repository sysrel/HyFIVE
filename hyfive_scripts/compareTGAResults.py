import sys

# $1=result1
# $2=result2

tainted_tuples1 = set() 
tainted_tuples2 = set() 
entry_to_copy_tainted1 = set()
entry_to_copy_tainted2 = set()
entry_to_reading_tainted1 = set()
entry_to_reading_tainted2 = set()
unique_entry1 = set()
unique_entry2 = set()


def extractTuples(fname, tainted_tuples):
    with open(fname, 'r') as frs:
            while True: 
                 line = frs.readline().strip()
                 if line == "":
                    break
                 if not "Tainted addresses:" in line:
                    continue
                 ps = line.split(' ')
                 for tuple in ps:
                     ts = tuple.split(',') 
                     if not len(ts) == 2: 
                        continue  
                     #print(f"{ts[0]},{ts[1]}")
                     tainted_tuples.add((ts[0],ts[1]))

def extractEntry(fname, entry, str=""): 
    #print(f"Extracting for {str} size {len(entry)}")
    with open(fname, 'r') as frs:
            while True: 
                 line = frs.readline().strip()
                 if line == "":
                    break
                 if not str == "" and not str in line:
                    continue
                 if not ":" in line:
                    continue
                 #print(f"line {line}")
                 addr = line.split(':')[1].split(' ')[1]
                 entry.add(addr)
                 #print(f"found {str}: {addr} size {len(entry)} entry {entry}")

def diff(e1, e2):
    for e in e1:
        if not e in e2:
           print(f"\t{e}")

def printResults(type):
    tuplesDiffer = not len(tainted_tuples1) == len(tainted_tuples2)
    print(f"Tainted tuples sizes {len(tainted_tuples1)} vs {len(tainted_tuples2)}, differ? {tuplesDiffer}")
    copyentriesDiffer = not len(entry_to_copy_tainted1) == len(entry_to_copy_tainted2)
    print(f"Tainting copy entries sizes {len(entry_to_copy_tainted1)} vs {len(entry_to_copy_tainted2)}, differ? {copyentriesDiffer}")
    print(f"Only with {type}:")
    diff(entry_to_copy_tainted1, entry_to_copy_tainted2)
    print(f"Only without {type}:")
    diff(entry_to_copy_tainted2, entry_to_copy_tainted1)
    readentriesDiffer = not len(entry_to_reading_tainted1) == len(entry_to_reading_tainted2)
    print(f"Tainted read entries sizes {len(entry_to_reading_tainted1)} vs {len(entry_to_reading_tainted2)}, differ? {readentriesDiffer}")
    print(f"Only with {type}:")
    diff(entry_to_reading_tainted1, entry_to_reading_tainted2)
    print(f"Only without {type}:")
    diff(entry_to_reading_tainted2, entry_to_reading_tainted1)
    uniqueentriesDiffer = not len(unique_entry1) == len(unique_entry2)
    print(f"Unique entries sizes {len(unique_entry1)} vs {len(unique_entry2)}, differ? {uniqueentriesDiffer}")
    print(f"Only with {type}:")
    diff(unique_entry1, unique_entry2)    
    print(f"Only without {type}:")
    diff(unique_entry2, unique_entry1)    

if __name__ == "__main__":
    if len(sys.argv) >= 4:
       extractTuples(sys.argv[1], tainted_tuples1)
       extractTuples(sys.argv[2], tainted_tuples2)
       extractEntry(sys.argv[1], entry_to_copy_tainted1, "[TAINTING COPY")
       extractEntry(sys.argv[2], entry_to_copy_tainted2, "[TAINTING COPY")
       extractEntry(sys.argv[1], entry_to_reading_tainted1, "[TAINTED READING")
       extractEntry(sys.argv[2], entry_to_reading_tainted2, "[TAINTED READING")
       extractEntry(sys.argv[1], unique_entry1, "[UNIQUE")
       extractEntry(sys.argv[2], unique_entry2, "[UNIQUE")
       printResults(sys.argv[3])
