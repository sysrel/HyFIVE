import sys

if __name__ == "__main__":
    if len(sys.argv) >= 2:
       with open(sys.argv[1], 'r') as frs:
            while True: 
                 line = frs.readline().strip()
                 if line == "":
                    break
                 ps = line.split(' ')
                 for tuple in ps:
                     ts = tuple.split(',') 
                     if not len(ts) == 2: 
                        continue  
                     if not int(ts[1], 16) == 0:
                        print(f"{ts[0]},{ts[1]}")
              


