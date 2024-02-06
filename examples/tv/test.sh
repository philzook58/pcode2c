


#1. just run
#2 cbmc / fuzz

# loop over all C files in directory except harness.c

#for x in *.c; do
#    if [ $x == "harness.c" ]; then
#        continue
#    fi
x=$1
printf "Running $x\n"
gcc $x -c -o /tmp/a.o 
python3 -m pcode2c --headers /tmp/a.o > decomp.c
gcc -Wpedantic -Wall -Wextra -Wno-format -I ../../templates $x harness.c
./a.out
#rm decomp.c
#done







