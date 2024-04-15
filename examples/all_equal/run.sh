gcc -Og -g -Wall -Wextra -std=c11 /tmp/all_equal.c -o all_equal 
objdump -l -F -d -S all_equal | grep -A 30 '<equal>' > all_equal.asm
python3 -m pcode2c all_equal --start-address 0x1169 --file-offset 0x1169 --size 0x2b > all_equal_pcode.c
gcc harness.c
./a.out