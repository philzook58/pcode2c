gcc hello.c
objdump -d a.out > a.out.s
readelf -a a.out > a.out.elf
python3 patch.py
objdump -d a_patched.out > a_patched.out.s
diff a.out.s a_patched.out.s