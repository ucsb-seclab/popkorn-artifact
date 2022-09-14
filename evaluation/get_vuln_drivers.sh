#!/bin/bash

# set -x

for f in $@/*/vulnerable
do
    echo $f
done | xargs -l1 echo | sed 's/\// /g' | awk '{print $3}' | sort | uniq -c
