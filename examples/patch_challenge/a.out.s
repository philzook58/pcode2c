
a.out:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 8a 2f 00 00    	push   0x2f8a(%rip)        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 8b 2f 00 00 	bnd jmp *0x2f8b(%rip)        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	push   $0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    105f:	90                   	nop

Disassembly of section .plt.got:

0000000000001060 <__cxa_finalize@plt>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	f2 ff 25 8d 2f 00 00 	bnd jmp *0x2f8d(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    106b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001070 <__stack_chk_fail@plt>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	f2 ff 25 45 2f 00 00 	bnd jmp *0x2f45(%rip)        # 3fc0 <__stack_chk_fail@GLIBC_2.4>
    107b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001080 <printf@plt>:
    1080:	f3 0f 1e fa          	endbr64 
    1084:	f2 ff 25 3d 2f 00 00 	bnd jmp *0x2f3d(%rip)        # 3fc8 <printf@GLIBC_2.2.5>
    108b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001090 <__assert_fail@plt>:
    1090:	f3 0f 1e fa          	endbr64 
    1094:	f2 ff 25 35 2f 00 00 	bnd jmp *0x2f35(%rip)        # 3fd0 <__assert_fail@GLIBC_2.2.5>
    109b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000010a0 <_start>:
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	31 ed                	xor    %ebp,%ebp
    10a6:	49 89 d1             	mov    %rdx,%r9
    10a9:	5e                   	pop    %rsi
    10aa:	48 89 e2             	mov    %rsp,%rdx
    10ad:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    10b1:	50                   	push   %rax
    10b2:	54                   	push   %rsp
    10b3:	45 31 c0             	xor    %r8d,%r8d
    10b6:	31 c9                	xor    %ecx,%ecx
    10b8:	48 8d 3d fe 01 00 00 	lea    0x1fe(%rip),%rdi        # 12bd <main>
    10bf:	ff 15 13 2f 00 00    	call   *0x2f13(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    10c5:	f4                   	hlt    
    10c6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    10cd:	00 00 00 

00000000000010d0 <deregister_tm_clones>:
    10d0:	48 8d 3d 39 2f 00 00 	lea    0x2f39(%rip),%rdi        # 4010 <__TMC_END__>
    10d7:	48 8d 05 32 2f 00 00 	lea    0x2f32(%rip),%rax        # 4010 <__TMC_END__>
    10de:	48 39 f8             	cmp    %rdi,%rax
    10e1:	74 15                	je     10f8 <deregister_tm_clones+0x28>
    10e3:	48 8b 05 f6 2e 00 00 	mov    0x2ef6(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    10ea:	48 85 c0             	test   %rax,%rax
    10ed:	74 09                	je     10f8 <deregister_tm_clones+0x28>
    10ef:	ff e0                	jmp    *%rax
    10f1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10f8:	c3                   	ret    
    10f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001100 <register_tm_clones>:
    1100:	48 8d 3d 09 2f 00 00 	lea    0x2f09(%rip),%rdi        # 4010 <__TMC_END__>
    1107:	48 8d 35 02 2f 00 00 	lea    0x2f02(%rip),%rsi        # 4010 <__TMC_END__>
    110e:	48 29 fe             	sub    %rdi,%rsi
    1111:	48 89 f0             	mov    %rsi,%rax
    1114:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1118:	48 c1 f8 03          	sar    $0x3,%rax
    111c:	48 01 c6             	add    %rax,%rsi
    111f:	48 d1 fe             	sar    %rsi
    1122:	74 14                	je     1138 <register_tm_clones+0x38>
    1124:	48 8b 05 c5 2e 00 00 	mov    0x2ec5(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    112b:	48 85 c0             	test   %rax,%rax
    112e:	74 08                	je     1138 <register_tm_clones+0x38>
    1130:	ff e0                	jmp    *%rax
    1132:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1138:	c3                   	ret    
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <__do_global_dtors_aux>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	80 3d c5 2e 00 00 00 	cmpb   $0x0,0x2ec5(%rip)        # 4010 <__TMC_END__>
    114b:	75 2b                	jne    1178 <__do_global_dtors_aux+0x38>
    114d:	55                   	push   %rbp
    114e:	48 83 3d a2 2e 00 00 	cmpq   $0x0,0x2ea2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1155:	00 
    1156:	48 89 e5             	mov    %rsp,%rbp
    1159:	74 0c                	je     1167 <__do_global_dtors_aux+0x27>
    115b:	48 8b 3d a6 2e 00 00 	mov    0x2ea6(%rip),%rdi        # 4008 <__dso_handle>
    1162:	e8 f9 fe ff ff       	call   1060 <__cxa_finalize@plt>
    1167:	e8 64 ff ff ff       	call   10d0 <deregister_tm_clones>
    116c:	c6 05 9d 2e 00 00 01 	movb   $0x1,0x2e9d(%rip)        # 4010 <__TMC_END__>
    1173:	5d                   	pop    %rbp
    1174:	c3                   	ret    
    1175:	0f 1f 00             	nopl   (%rax)
    1178:	c3                   	ret    
    1179:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001180 <frame_dummy>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	e9 77 ff ff ff       	jmp    1100 <register_tm_clones>

0000000000001189 <add3>:
    1189:	f3 0f 1e fa          	endbr64 
    118d:	55                   	push   %rbp
    118e:	48 89 e5             	mov    %rsp,%rbp
    1191:	89 7d fc             	mov    %edi,-0x4(%rbp)
    1194:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1197:	83 c0 03             	add    $0x3,%eax
    119a:	5d                   	pop    %rbp
    119b:	c3                   	ret    

000000000000119c <add3_patch>:
    119c:	f3 0f 1e fa          	endbr64 
    11a0:	55                   	push   %rbp
    11a1:	48 89 e5             	mov    %rsp,%rbp
    11a4:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11a7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11aa:	83 c0 05             	add    $0x5,%eax
    11ad:	5d                   	pop    %rbp
    11ae:	c3                   	ret    

00000000000011af <delete_if>:
    11af:	f3 0f 1e fa          	endbr64 
    11b3:	55                   	push   %rbp
    11b4:	48 89 e5             	mov    %rsp,%rbp
    11b7:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11ba:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    11be:	75 07                	jne    11c7 <delete_if+0x18>
    11c0:	b8 00 00 00 00       	mov    $0x0,%eax
    11c5:	eb 05                	jmp    11cc <delete_if+0x1d>
    11c7:	b8 01 00 00 00       	mov    $0x1,%eax
    11cc:	5d                   	pop    %rbp
    11cd:	c3                   	ret    

00000000000011ce <delete_if_patch>:
    11ce:	f3 0f 1e fa          	endbr64 
    11d2:	55                   	push   %rbp
    11d3:	48 89 e5             	mov    %rsp,%rbp
    11d6:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11d9:	b8 01 00 00 00       	mov    $0x1,%eax
    11de:	5d                   	pop    %rbp
    11df:	c3                   	ret    

00000000000011e0 <insert_if>:
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	55                   	push   %rbp
    11e5:	48 89 e5             	mov    %rsp,%rbp
    11e8:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11eb:	b8 01 00 00 00       	mov    $0x1,%eax
    11f0:	5d                   	pop    %rbp
    11f1:	c3                   	ret    

00000000000011f2 <change_condition>:
    11f2:	f3 0f 1e fa          	endbr64 
    11f6:	55                   	push   %rbp
    11f7:	48 89 e5             	mov    %rsp,%rbp
    11fa:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11fd:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    1201:	78 07                	js     120a <change_condition+0x18>
    1203:	b8 00 00 00 00       	mov    $0x0,%eax
    1208:	eb 05                	jmp    120f <change_condition+0x1d>
    120a:	b8 01 00 00 00       	mov    $0x1,%eax
    120f:	5d                   	pop    %rbp
    1210:	c3                   	ret    

0000000000001211 <delete_assign>:
    1211:	f3 0f 1e fa          	endbr64 
    1215:	55                   	push   %rbp
    1216:	48 89 e5             	mov    %rsp,%rbp
    1219:	89 7d fc             	mov    %edi,-0x4(%rbp)
    121c:	83 45 fc 07          	addl   $0x7,-0x4(%rbp)
    1220:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1223:	5d                   	pop    %rbp
    1224:	c3                   	ret    

0000000000001225 <swap_statement>:
    1225:	f3 0f 1e fa          	endbr64 
    1229:	55                   	push   %rbp
    122a:	48 89 e5             	mov    %rsp,%rbp
    122d:	48 8d 05 d0 0d 00 00 	lea    0xdd0(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1234:	48 89 c7             	mov    %rax,%rdi
    1237:	b8 00 00 00 00       	mov    $0x0,%eax
    123c:	e8 3f fe ff ff       	call   1080 <printf@plt>
    1241:	48 8d 05 c2 0d 00 00 	lea    0xdc2(%rip),%rax        # 200a <_IO_stdin_used+0xa>
    1248:	48 89 c7             	mov    %rax,%rdi
    124b:	b8 00 00 00 00       	mov    $0x0,%eax
    1250:	e8 2b fe ff ff       	call   1080 <printf@plt>
    1255:	90                   	nop
    1256:	5d                   	pop    %rbp
    1257:	c3                   	ret    

0000000000001258 <replace_const>:
    1258:	f3 0f 1e fa          	endbr64 
    125c:	55                   	push   %rbp
    125d:	48 89 e5             	mov    %rsp,%rbp
    1260:	48 83 ec 50          	sub    $0x50,%rsp
    1264:	89 7d bc             	mov    %edi,-0x44(%rbp)
    1267:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    126e:	00 00 
    1270:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1274:	31 c0                	xor    %eax,%eax
    1276:	8b 45 bc             	mov    -0x44(%rbp),%eax
    1279:	89 45 d0             	mov    %eax,-0x30(%rbp)
    127c:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    1283:	eb 19                	jmp    129e <replace_const+0x46>
    1285:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1288:	83 e8 01             	sub    $0x1,%eax
    128b:	48 98                	cltq   
    128d:	8b 54 85 d0          	mov    -0x30(%rbp,%rax,4),%edx
    1291:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1294:	48 98                	cltq   
    1296:	89 54 85 d0          	mov    %edx,-0x30(%rbp,%rax,4)
    129a:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
    129e:	83 7d cc 09          	cmpl   $0x9,-0x34(%rbp)
    12a2:	7e e1                	jle    1285 <replace_const+0x2d>
    12a4:	8b 45 f4             	mov    -0xc(%rbp),%eax
    12a7:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    12ab:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    12b2:	00 00 
    12b4:	74 05                	je     12bb <replace_const+0x63>
    12b6:	e8 b5 fd ff ff       	call   1070 <__stack_chk_fail@plt>
    12bb:	c9                   	leave  
    12bc:	c3                   	ret    

00000000000012bd <main>:
    12bd:	f3 0f 1e fa          	endbr64 
    12c1:	55                   	push   %rbp
    12c2:	48 89 e5             	mov    %rsp,%rbp
    12c5:	53                   	push   %rbx
    12c6:	48 83 ec 08          	sub    $0x8,%rsp
    12ca:	bf 03 00 00 00       	mov    $0x3,%edi
    12cf:	e8 b5 fe ff ff       	call   1189 <add3>
    12d4:	89 c3                	mov    %eax,%ebx
    12d6:	bf 03 00 00 00       	mov    $0x3,%edi
    12db:	e8 bc fe ff ff       	call   119c <add3_patch>
    12e0:	39 c3                	cmp    %eax,%ebx
    12e2:	74 28                	je     130c <main+0x4f>
    12e4:	48 8d 05 46 0d 00 00 	lea    0xd46(%rip),%rax        # 2031 <__PRETTY_FUNCTION__.0>
    12eb:	48 89 c1             	mov    %rax,%rcx
    12ee:	ba 55 00 00 00       	mov    $0x55,%edx
    12f3:	48 8d 05 16 0d 00 00 	lea    0xd16(%rip),%rax        # 2010 <_IO_stdin_used+0x10>
    12fa:	48 89 c6             	mov    %rax,%rsi
    12fd:	48 8d 05 14 0d 00 00 	lea    0xd14(%rip),%rax        # 2018 <_IO_stdin_used+0x18>
    1304:	48 89 c7             	mov    %rax,%rdi
    1307:	e8 84 fd ff ff       	call   1090 <__assert_fail@plt>
    130c:	b8 00 00 00 00       	mov    $0x0,%eax
    1311:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
    1315:	c9                   	leave  
    1316:	c3                   	ret    

Disassembly of section .fini:

0000000000001318 <_fini>:
    1318:	f3 0f 1e fa          	endbr64 
    131c:	48 83 ec 08          	sub    $0x8,%rsp
    1320:	48 83 c4 08          	add    $0x8,%rsp
    1324:	c3                   	ret    
