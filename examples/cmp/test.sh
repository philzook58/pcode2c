gcc -c cmpxchg.s
python3 -m pcode2c cmpxchg.o > decomp.c
gcc -c decomp.c