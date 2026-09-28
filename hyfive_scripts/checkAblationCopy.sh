#!/bin/bash

benchmark_top_level=$1
outfile=$2
type=$3
scriptspath=/home/tuba/Documents/experiments/HYFIVE_Experiments/scripts/
for benchdir in $benchmark_top_level/*; do
    #echo $benchdir" "$(basename "$benchdir")
    basedir=$(basename "$benchdir")
    benchpath=$benchmark_top_level/$basedir
    cfa=alltraces_indirect_taint_poc_3_ret_reduced_cfa.txt
    #nocopy=alltraces_indirect_taint_poc_3_ablation_no_copy.txt
    notype=alltraces_indirect_taint_poc_3_ablation_no_$type.txt
    if [ ! -f $benchpath/$cfa ]; then
       continue
    fi
    if [ ! -f $benchpath/$notype ]; then
       continue
    fi
    echo "Comparing for directory "$basedir" using files"$cfa" and "$notype
    echo "Comparing for directory "$basedir" using files"$cfa" and "$notype >> $outfile
    python3 $scriptspath/compareTGAResults.py $benchpath/$cfa $benchpath/$notype $type >> $outfile
done
