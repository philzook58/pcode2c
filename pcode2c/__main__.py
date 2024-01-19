from pypcode import Context, PcodePrettyPrinter
import argparse

from elftools.elf.elffile import ELFFile

from .printer import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="pcode2c", description="Convert pcode to C code"
    )
    parser.add_argument("filename")
    # parser.add_argument("-f", "--function")
    # parser.add_argument("-a", "--address")
    parser.add_argument("-b", "--langid")
    # parser.add_argument("-o", "--output")
    args = parser.parse_args()
    with open(args.filename, "rb") as file:
        elffile = ELFFile(file)

        # Get the symbol table
        # symtab = elffile.get_section_by_name(".symtab")
        # Search for the function in the symbol table
        # for symbol in symtab.iter_symbols():
        #    if symbol.name == function_name:
        #        addr = symbol['st_value']

        # Iterate over sections and find the .text section
        for section in elffile.iter_sections():
            if section.name == ".text":
                offset = section.header["sh_offset"]
                size = section.header["sh_size"]
                file.seek(offset)
                code = file.read(size)
                break

    langid = args.langid or "x86:LE:64:default"
    ctx = Context(langid)
    dx = ctx.disassemble(code)
    insns = {insn.addr.offset: insn for insn in dx.instructions}
    # print(fmt_arch_header(ctx))
    res = ctx.translate(code)
    for op in res.ops:
        if op.opcode == pypcode.OpCode.IMARK:
            assert len(op.inputs) == 1
            addr = op.inputs[0].offset
            ins = insns[addr]
            print(
                f"""
        case 0x{addr:x}:
            INSN(0x{addr:x},"{ins.addr.offset:#x}: {ins.mnem} {ins.body}")
            """
            )
        else:
            print("//", PcodePrettyPrinter.fmt_op(op))
            print(fmt_insn(op))
            if op.opcode == pypcode.OpCode.RETURN:
                print("return;")
