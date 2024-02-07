.extern _start
_start:
    cmp %eax,%ebx
    cmove %ecx, %edx
    cmpxchg %edx,(%rdi)
    nop # there is a slight bug when a jump can occur to the end
    

