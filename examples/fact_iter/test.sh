gcc -g -O1 fact.c -c  # try clang
objdump -S -d --dwarf=info fact.o > fact.s
python3 -m pcode2c.dwarf_annot fact.o