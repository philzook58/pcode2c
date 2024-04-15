0000000000001169 <equal> (File Offset: 0x1169):
equal():
/tmp/all_equal.c:3
#include <stdbool.h>
#include <assert.h>
bool equal(int n, int a[], int b[]){
    1169:	f3 0f 1e fa          	endbr64 
/tmp/all_equal.c:4
    for(int i = 0; i < n; i++){
    116d:	b8 00 00 00 00       	mov    $0x0,%eax
    1172:	eb 03                	jmp    1177 <equal+0xe> (File Offset: 0x1177)
/tmp/all_equal.c:4 (discriminator 2)
    1174:	83 c0 01             	add    $0x1,%eax
/tmp/all_equal.c:4 (discriminator 1)
    1177:	39 f8                	cmp    %edi,%eax
    1179:	7d 13                	jge    118e <equal+0x25> (File Offset: 0x118e)
/tmp/all_equal.c:5
        if(a[i] != b[i]){
    117b:	48 63 c8             	movslq %eax,%rcx
    117e:	44 8b 04 8a          	mov    (%rdx,%rcx,4),%r8d
    1182:	44 39 04 8e          	cmp    %r8d,(%rsi,%rcx,4)
    1186:	74 ec                	je     1174 <equal+0xb> (File Offset: 0x1174)
/tmp/all_equal.c:6
            return false;
    1188:	b8 00 00 00 00       	mov    $0x0,%eax
/tmp/all_equal.c:10
        }
    }
    return true;
}
    118d:	c3                   	ret    
--
    11b7:	e8 ad ff ff ff       	call   1169 <equal> (File Offset: 0x1169)
    11bc:	84 c0                	test   %al,%al
    11be:	74 1a                	je     11da <main+0x46> (File Offset: 0x11da)
/tmp/all_equal.c:15
}
    11c0:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
    11c5:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    11cc:	00 00 
    11ce:	75 29                	jne    11f9 <main+0x65> (File Offset: 0x11f9)
    11d0:	b8 00 00 00 00       	mov    $0x0,%eax
    11d5:	48 83 c4 38          	add    $0x38,%rsp
    11d9:	c3                   	ret    
/tmp/all_equal.c:14 (discriminator 1)
    assert(equal(10, a, a));
    11da:	48 8d 0d 44 0e 00 00 	lea    0xe44(%rip),%rcx        # 2025 <__PRETTY_FUNCTION__.0> (File Offset: 0x2025)
    11e1:	ba 0e 00 00 00       	mov    $0xe,%edx
    11e6:	48 8d 35 17 0e 00 00 	lea    0xe17(%rip),%rsi        # 2004 <_IO_stdin_used+0x4> (File Offset: 0x2004)
    11ed:	48 8d 3d 21 0e 00 00 	lea    0xe21(%rip),%rdi        # 2015 <_IO_stdin_used+0x15> (File Offset: 0x2015)
    11f4:	e8 77 fe ff ff       	call   1070 <__assert_fail@plt> (File Offset: 0x1070)
/tmp/all_equal.c:15
}
    11f9:	e8 62 fe ff ff       	call   1060 <__stack_chk_fail@plt> (File Offset: 0x1060)

Disassembly of section .fini:

0000000000001200 <_fini> (File Offset: 0x1200):
_fini():
    1200:	f3 0f 1e fa          	endbr64 
    1204:	48 83 ec 08          	sub    $0x8,%rsp
    1208:	48 83 c4 08          	add    $0x8,%rsp
    120c:	c3                   	ret    
