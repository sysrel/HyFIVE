echo "Taint analysis results for benchmark "$1" based on result file "$2
echo "=========Locations propagating taint:========="
#grep "\[TAINT," $2  | cut -d " " -f 15 | sort | uniq
#grep "\[TAINT," $2  | cut -d " " -f 15 | sort | uniq | wc -l
grep "\[TAINT," $2  | cut -d " " -f 15 | sort | uniq | python3 $HYFIVE_RESULTS/scripts/addr2FuncMap.py $1
echo "=========Locations propagating taint via copy functions:========="
grep "\[TAINT VIA" $2 | cut -d " " -f 17 | sort | uniq | python3 $HYFIVE_RESULTS/scripts/addr2FuncMap.py $1
echo "=========Locations read tainted:========="
grep "\[READ TAINT" $2 | cut -d " " -f 10 | sort | uniq | python3 $HYFIVE_RESULTS/scripts/addr2FuncMap.py $1
echo "=========Locations use tainted:========="
grep "\[USE " $2 | cut -d " " -f 14 | sort | uniq | python3 $HYFIVE_RESULTS/scripts/addr2FuncMap.py $1
