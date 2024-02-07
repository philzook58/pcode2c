python3 -m pcode2c a.out > decomp.c
objdump a.out -d > objdump
readelf -a a.out > readelf