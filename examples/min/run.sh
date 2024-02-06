
python3 -m pcode2c mymin.o > decomp.c
cbmc harness.c 
