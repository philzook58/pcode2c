gcc -no-pie  hello.c
objdump a.out -d > objdump
readelf -a a.out > readelf
python3 -m pcode2c a.out > decomp.c
gcc -c decomp.c