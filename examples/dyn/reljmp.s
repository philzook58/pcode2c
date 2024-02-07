
.extern _start
_start:
    foo:
    add $1, %eax
    nop
    nop
    nop
    .rept 0x1000
    nop
     .endr
    jmp foo
