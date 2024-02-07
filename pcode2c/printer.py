import pypcode


def fmt_arch_header(langid):
    ctx = Context(langid)
    output = []
    for reg, vnode in ctx.registers.items():
        output.append(f"#define {reg} 0x{vnode.offset:x}")
    return output


def fmt_symbol_header(elf):
    # Get the symbol table
    output = []
    symtab = elffile.get_section_by_name(".symtab")
    for symbol in symtab.iter_symbols():
        output.append(f'#define {symbol.name} {symbol["st_value"]})')
    return output


# import importlib
# with importlib.resources("pcode2c.include", "_pcode2c.h") as f:
#    pcode2c_include = f.read()


def is_branch(op: pypcode.OpCode):
    return op in (
        pypcode.OpCode.BRANCH,
        pypcode.OpCode.CBRANCH,
        pypcode.OpCode.BRANCHIND,
        pypcode.OpCode.CALL,
        pypcode.OpCode.CALLIND,
        pypcode.OpCode.RETURN,
    )


def fmt_varnode(varnode: pypcode.Varnode):
    if varnode.space.name == "const":
        return (
            "(uint8_t *)&(long unsigned int){"
            + hex(varnode.offset)
            + "ul}, "
            + hex(varnode.size)
            + "ul"
        )

    regname = varnode.getRegisterName()
    if regname != "":
        regname = f" /* {regname} */"
    return f"{varnode.space.name}_space + {hex(varnode.offset)}ul{regname}, {varnode.size}ul"


def fmt_varnode_separate_space(varnode: pypcode.Varnode):
    if varnode.space.name == "const":
        return (
            "0, (uint8_t *)&(long unsigned int){"
            + hex(varnode.offset)
            + "ul}, "
            + hex(varnode.size)
            + "ul"
        )
    regname = varnode.getRegisterName()
    if regname != "":
        regname = f" /* {regname} */"
    return f"{varnode.space.name}_space, {hex(varnode.offset)}ul{regname}, {varnode.size}ul"


unique_pcode_insn_id = 0


def fmt_branch_dest_varnode(varnode):
    # Special case this generation to support realtive pcode jumps
    if varnode.space.name == "const":
        return (
            "0, P_"
            + hex(varnode.offset + unique_pcode_insn_id)
            + ", "
            + hex(varnode.size)
            + "ul"
        )
    elif varnode.space.name == "ram":
        return f"{varnode.space.name}_space, {hex(varnode.offset)}ul, {varnode.size}ul"
    else:
        raise ValueError(f"Bad branch dest space {varnode.space.name}")


def fmt_insn(op: pypcode.PcodeOp):
    global unique_pcode_insn_id
    unique_pcode_insn_id += 1
    args = [fmt_varnode(op.output)] if op.output else []
    args.extend(fmt_varnode(varnode) for varnode in op.inputs)
    args = ", ".join(args)
    opcode = str(op.opcode).replace("pypcode.pypcode_native.OpCode.", "")
    if op.opcode == pypcode.OpCode.BRANCH:
        return f"L_P_{hex(unique_pcode_insn_id)}: BRANCH_GOTO_TEMPFIX({fmt_branch_dest_varnode(op.inputs[0])});"
    elif op.opcode == pypcode.OpCode.CBRANCH:
        args = (
            fmt_branch_dest_varnode(op.inputs[0])
            + ", "
            + fmt_varnode_separate_space(op.inputs[1])
        )
        return f"L_P_{hex(unique_pcode_insn_id)}: CBRANCH_GOTO_TEMPFIX({args});"
    else:
        return f"L_P_{hex(unique_pcode_insn_id)}: {opcode}({args});"


header = """\
/* AUTOGENERATED. DO NOT EDIT. */
#include "_pcode.h"
void pcode2c(CPUState *state, size_t breakpoint){
    uint8_t* register_space = state->reg; 
    uint8_t* unique_space = state->unique; 
    uint8_t* ram_space = state->ram;
    uint8_t* ram = ram_space; // TODO: remove this
    for(;;){
    switch(state->pc){"""

footer = """\
        default: assert(state->pc != -1); // Unexpected PC value
}}}"""


from elftools.elf.elffile import ELFFile
from pypcode import Context, PcodePrettyPrinter


def pcode2c(filename, langid):
    output = []
    with open(filename, "rb") as file:
        elffile = ELFFile(file)

        # Get the symbol table
        # if args.function is not None:
        #    symtab = elffile.get_section_by_name(".symtab")
        # Search for the function in the symbol table
        #    for symbol in symtab.iter_symbols():
        #        if symbol.name == args.function:
        #            fun_addr = symbol["st_value"]
        e_type = elffile.header["e_type"]
        if e_type == "ET_EXEC":
            for segment in elffile.iter_segments():
                if segment["p_flags"] & 0x1:  # PF_X flag is 1
                    offset = segment["p_offset"]
                    base = segment["p_vaddr"]
                    size = segment["p_memsz"]
                    break

        elif e_type == "ET_DYN":
            # Iterate over sections and find the .text section
            for section in elffile.iter_sections():
                if section.name == ".text":
                    offset = section.header["sh_offset"]
                    size = section.header["sh_size"]
                    base = 0
                    break

        else:
            raise ValueError("Unknown ELF type")
        if size == 0:
            raise ValueError("No code found")
        file.seek(offset)
        code = file.read(size)

    ctx = Context(langid)
    dx = ctx.disassemble(code, base_address=base)
    insns = {insn.addr.offset: insn for insn in dx.instructions}
    # print(fmt_arch_header(ctx))
    res = ctx.translate(code, base_address=base)
    output.append(header)
    for op in res.ops:
        if op.opcode == pypcode.OpCode.IMARK:
            assert len(op.inputs) == 1
            addr = op.inputs[0].offset
            ins = insns[addr]
            output.append(
                f"""\
        case 0x{addr:x}:
        L_0x{addr:x}ul:
            INSN(0x{addr:x}ul,"{ins.addr.offset:#x}: {ins.mnem} {ins.body}")"""
            )
        else:
            # print("//", PcodePrettyPrinter.fmt_op(op))
            output.append("            " + fmt_insn(op))
    output.append(footer)
    return output


def single(precond, postcond, equality=False):
    return f"""\
int main(){{
    CPUState state;
    init_state(&state);
    __CPROVER_assume({precond});
    pcode2c(&state, -1);
    __CPROVER_assert({postcond});
}}"""


def comparative(precond, postcond, equality=False):
    return f"""\
int main(){{
    CPUState state_orig, state_mod;
    __CPROVER_assume({precond});
    pcode2c_orig(&state_orig, -1);
    pcode2c_mod(&state_mod, -1);
    __CPROVER_assert({postcond}, "Postcondition");
}}"""
