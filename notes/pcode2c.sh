#rm -rf /tmp/ghidraproject
#mkdir /tmp/ghidraproject
# -import $1
$GHIDRAHOME/support/analyzeHeadless /tmp/ghidraproject Project1 -process $1 -postScript pcode2c.py $2 #2>/dev/null
