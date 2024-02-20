
fact.o:     file format elf64-x86-64

Contents of the .debug_info section:

  Compilation Unit @ offset 0x0:
   Length:        0xa8 (32-bit)
   Version:       5
   Unit Type:     DW_UT_compile (1)
   Abbrev Offset: 0x0
   Pointer Size:  8
 <0><c>: Abbrev Number: 2 (DW_TAG_compile_unit)
    <d>   DW_AT_producer    : (indirect string, offset: 0x19): GNU C17 11.4.0 -mtune=generic -march=x86-64 -g -O1 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection
    <11>   DW_AT_language    : 29	(C11)
    <12>   DW_AT_name        : (indirect line string, offset: 0x39): fact.c
    <16>   DW_AT_comp_dir    : (indirect line string, offset: 0x0): /home/philip/Documents/python/pcode2c/examples/fact_iter
    <1a>   DW_AT_low_pc      : 0x0
    <22>   DW_AT_high_pc     : 0x1c
    <2a>   DW_AT_stmt_list   : 0x0
 <1><2e>: Abbrev Number: 3 (DW_TAG_subprogram)
    <2f>   DW_AT_external    : 1
    <2f>   DW_AT_name        : (indirect string, offset: 0x0): fact
    <33>   DW_AT_decl_file   : 1
    <34>   DW_AT_decl_line   : 7
    <35>   DW_AT_decl_column : 5
    <36>   DW_AT_prototyped  : 1
    <36>   DW_AT_type        : <0xa4>
    <3a>   DW_AT_low_pc      : 0x0
    <42>   DW_AT_high_pc     : 0x1c
    <4a>   DW_AT_frame_base  : 1 byte block: 9c 	(DW_OP_call_frame_cfa)
    <4c>   DW_AT_call_all_calls: 1
    <4c>   DW_AT_sibling     : <0xa4>
 <2><50>: Abbrev Number: 4 (DW_TAG_formal_parameter)
    <51>   DW_AT_name        : x
    <53>   DW_AT_decl_file   : 1
    <54>   DW_AT_decl_line   : 7
    <55>   DW_AT_decl_column : 14
    <56>   DW_AT_type        : <0xa4>
    <5a>   DW_AT_location    : 0x12 (location list)
    <5e>   DW_AT_GNU_locviews: 0xc
 <2><62>: Abbrev Number: 5 (DW_TAG_variable)
    <63>   DW_AT_name        : (indirect string, offset: 0xab): result
    <67>   DW_AT_decl_file   : 1
    <68>   DW_AT_decl_line   : 10
    <69>   DW_AT_decl_column : 9
    <6a>   DW_AT_type        : <0xa4>
    <6e>   DW_AT_location    : 0x2a (location list)
    <72>   DW_AT_GNU_locviews: 0x24
 <2><76>: Abbrev Number: 1 (DW_TAG_label)
    <77>   DW_AT_name        : (indirect string, offset: 0xf): loop_head
    <7b>   DW_AT_decl_file   : 1
    <7b>   DW_AT_decl_line   : 11
    <7c>   DW_AT_decl_column : 1
    <7d>   DW_AT_low_pc      : 0x4
 <2><85>: Abbrev Number: 1 (DW_TAG_label)
    <86>   DW_AT_name        : (indirect string, offset: 0xb2): loop_body
    <8a>   DW_AT_decl_file   : 1
    <8a>   DW_AT_decl_line   : 14
    <8b>   DW_AT_decl_column : 5
    <8c>   DW_AT_low_pc      : 0xd
 <2><94>: Abbrev Number: 1 (DW_TAG_label)
    <95>   DW_AT_name        : (indirect string, offset: 0x5): loop_exit
    <99>   DW_AT_decl_file   : 1
    <99>   DW_AT_decl_line   : 18
    <9a>   DW_AT_decl_column : 1
    <9b>   DW_AT_low_pc      : 0x1b
 <2><a3>: Abbrev Number: 0
 <1><a4>: Abbrev Number: 6 (DW_TAG_base_type)
    <a5>   DW_AT_byte_size   : 4
    <a6>   DW_AT_encoding    : 5	(signed)
    <a7>   DW_AT_name        : int
 <1><ab>: Abbrev Number: 0


Disassembly of section .text:

0000000000000000 <fact>:
!= form is classic problem wth given negative argument.

*/

int fact(int x)
{
   0:	f3 0f 1e fa          	endbr64 
    // fun_entry:
    int result = 1;
loop_head:
    while (x != 0)
   4:	85 ff                	test   %edi,%edi
   6:	74 0e                	je     16 <fact+0x16>
    int result = 1;
   8:	b8 01 00 00 00       	mov    $0x1,%eax
    {
    loop_body:
        result = result * x;
   d:	0f af c7             	imul   %edi,%eax
    while (x != 0)
  10:	83 ef 01             	sub    $0x1,%edi
  13:	75 f8                	jne    d <fact+0xd>
  15:	c3                   	ret    
    int result = 1;
  16:	b8 01 00 00 00       	mov    $0x1,%eax
        x = x - 1;
    }
loop_exit:
    return result;
  1b:	c3                   	ret    
