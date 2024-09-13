#!/usr/bin/env python
"""
Largely the same as https://github.com/angr/pypcode/blob/master/pypcode/__main__.py

Runs when invoking pypcode module from command line. Lists supported
architectures, and handles basic disassembly and translation to P-code of
supported binaries. Does not parse object files, the binary files must be plain
machine code bytes in a file.
"""

import pypcode
import argparse
import logging
import sys
from difflib import SequenceMatcher
from .printer import is_branch
from collections import defaultdict
from pypcode import (
    PcodeOp,
    Arch,
    BadDataError,
    Context,
    OpCode,
    TranslateFlags,
    UnimplError,
    Varnode,
)


class OpFormat:
    """
    General op pretty-printer.
    """

    @staticmethod
    def fmt_vn(vn: Varnode) -> str:
        if vn.space.name == "const":
            return "%#x" % vn.offset
        elif vn.space.name == "register":
            name = vn.getRegisterName()
            if name:
                return name
        elif vn.space.name == "unique":
            return f"unique_{vn.offset:x}_{vn.size:d}"
        return f"{vn.space.name}[{vn.offset:x}:{vn.size:d}]"

    def fmt(self, op: PcodeOp) -> str:
        return f'{op.opcode.__name__} {", ".join(self.fmt_vn(i) for i in op.inputs)}'


class OpFormatUnary(OpFormat):
    """
    General unary op pretty-printer.
    """

    __slots__ = ("operator",)

    def __init__(self, operator: str):
        super().__init__()
        self.operator = operator

    def fmt(self, op: PcodeOp) -> str:
        return f"{self.operator}{self.fmt_vn(op.inputs[0])}"


class OpFormatBinary(OpFormat):
    """
    General binary op pretty-printer.
    """

    __slots__ = ("operator",)

    def __init__(self, operator: str):
        super().__init__()
        self.operator = operator

    def fmt(self, op: PcodeOp) -> str:
        return (
            f"{self.fmt_vn(op.inputs[0])} {self.operator} {self.fmt_vn(op.inputs[1])}"
        )


class OpFormatFunc(OpFormat):
    """
    Function-call style op pretty-printer.
    """

    __slots__ = ("operator",)

    def __init__(self, operator: str):
        super().__init__()
        self.operator = operator

    def fmt(self, op: PcodeOp) -> str:
        return f'{self.operator}({", ".join(self.fmt_vn(i) for i in op.inputs)})'


def label(vn: Varnode):
    assert vn.space.name == "ram"
    return f"L{vn.offset:#x}"


class OpFormatSpecial(OpFormat):
    """
    Specialized op pretty-printers.
    """

    def fmt_BRANCH(self, op: PcodeOp) -> str:
        return f"goto {label(op.inputs[0])}"

    def fmt_BRANCHIND(self, op: PcodeOp) -> str:
        return f"goto [{self.fmt_vn(op.inputs[0])}]"

    def fmt_CALL(self, op: PcodeOp) -> str:
        return f"call {self.fmt_vn(op.inputs[0])}"

    def fmt_CALLIND(self, op: PcodeOp) -> str:
        return f"call [{self.fmt_vn(op.inputs[0])}]"

    def fmt_CBRANCH(self, op: PcodeOp) -> str:
        return f"if ({self.fmt_vn(op.inputs[1])}) goto {label(op.inputs[0])}"

    def fmt_LOAD(self, op: PcodeOp) -> str:
        assert op.inputs[0].getSpaceFromConst().name == "ram"
        return f"memmove(&({self.fmt_vn(op.output)}), ram + {self.fmt_vn(op.inputs[1])}, {op.output.size})"
        # return f"*[{op.inputs[0].getSpaceFromConst().name}]{self.fmt_vn(op.inputs[1])}"

    def fmt_RETURN(self, op: PcodeOp) -> str:
        return "return"
        # return f"return; //{self.fmt_vn(op.inputs[0])}"

    def fmt_STORE(self, op: PcodeOp) -> str:
        assert op.inputs[0].getSpaceFromConst().name == "ram"
        return f"memmove(ram + {self.fmt_vn(op.inputs[1])}, &({self.fmt_vn(op.inputs[2])}), {op.inputs[2].size})"
        # return f"*[{op.inputs[0].getSpaceFromConst().name}]{self.fmt_vn(op.inputs[1])} = {self.fmt_vn(op.inputs[2])}"

    def fmt(self, op: PcodeOp) -> str:
        return {
            OpCode.BRANCH: self.fmt_BRANCH,
            OpCode.BRANCHIND: self.fmt_BRANCHIND,
            OpCode.CALL: self.fmt_CALL,
            OpCode.CALLIND: self.fmt_CALLIND,
            OpCode.CBRANCH: self.fmt_CBRANCH,
            OpCode.LOAD: self.fmt_LOAD,
            OpCode.RETURN: self.fmt_RETURN,
            OpCode.STORE: self.fmt_STORE,
        }.get(op.opcode, super().fmt)(op)


class PcodePrettyPrinter:
    """
    P-code pretty-printer.
    """

    DEFAULT_OP_FORMAT = OpFormat()

    OP_FORMATS = {
        OpCode.BOOL_AND: OpFormatBinary("&&"),
        OpCode.BOOL_NEGATE: OpFormatUnary("!"),
        OpCode.BOOL_OR: OpFormatBinary("||"),
        OpCode.BOOL_XOR: OpFormatBinary("^^"),
        OpCode.BRANCH: OpFormatSpecial(),
        OpCode.BRANCHIND: OpFormatSpecial(),
        OpCode.CALL: OpFormatSpecial(),
        OpCode.CALLIND: OpFormatSpecial(),
        OpCode.CBRANCH: OpFormatSpecial(),
        OpCode.COPY: OpFormatUnary(""),
        OpCode.CPOOLREF: OpFormatFunc("cpool"),
        OpCode.FLOAT_ABS: OpFormatFunc("abs"),
        OpCode.FLOAT_ADD: OpFormatBinary("f+"),
        OpCode.FLOAT_CEIL: OpFormatFunc("ceil"),
        OpCode.FLOAT_DIV: OpFormatBinary("f/"),
        OpCode.FLOAT_EQUAL: OpFormatBinary("f=="),
        OpCode.FLOAT_FLOAT2FLOAT: OpFormatFunc("float2float"),
        OpCode.FLOAT_FLOOR: OpFormatFunc("floor"),
        OpCode.FLOAT_INT2FLOAT: OpFormatFunc("int2float"),
        OpCode.FLOAT_LESS: OpFormatBinary("f<"),
        OpCode.FLOAT_LESSEQUAL: OpFormatBinary("f<="),
        OpCode.FLOAT_MULT: OpFormatBinary("f*"),
        OpCode.FLOAT_NAN: OpFormatFunc("nan"),
        OpCode.FLOAT_NEG: OpFormatUnary("f- "),
        OpCode.FLOAT_NOTEQUAL: OpFormatBinary("f!="),
        OpCode.FLOAT_ROUND: OpFormatFunc("round"),
        OpCode.FLOAT_SQRT: OpFormatFunc("sqrt"),
        OpCode.FLOAT_SUB: OpFormatBinary("f-"),
        OpCode.FLOAT_TRUNC: OpFormatFunc("trunc"),
        OpCode.INT_2COMP: OpFormatUnary("-"),
        OpCode.INT_ADD: OpFormatBinary("+"),
        OpCode.INT_AND: OpFormatBinary("&"),
        OpCode.INT_CARRY: OpFormatFunc("carry"),
        OpCode.INT_DIV: OpFormatBinary("/"),
        OpCode.INT_EQUAL: OpFormatBinary("=="),
        OpCode.INT_LEFT: OpFormatBinary("<<"),
        OpCode.INT_LESS: OpFormatBinary("<"),
        OpCode.INT_LESSEQUAL: OpFormatBinary("<="),
        OpCode.INT_MULT: OpFormatBinary("*"),
        OpCode.INT_NEGATE: OpFormatUnary("~"),
        OpCode.INT_NOTEQUAL: OpFormatBinary("!="),
        OpCode.INT_OR: OpFormatBinary("|"),
        OpCode.INT_REM: OpFormatBinary("%"),
        OpCode.INT_RIGHT: OpFormatBinary(">>"),
        OpCode.INT_SBORROW: OpFormatFunc("sborrow"),
        OpCode.INT_SCARRY: OpFormatFunc("scarry"),
        OpCode.INT_SDIV: OpFormatFunc("sdiv"),
        OpCode.INT_SEXT: OpFormatFunc("sext"),
        OpCode.INT_SLESS: OpFormatFunc("sless"),
        OpCode.INT_SLESSEQUAL: OpFormatFunc("slessequal"),
        OpCode.INT_SREM: OpFormatBinary("srem"),
        OpCode.INT_SRIGHT: OpFormatFunc("sright"),
        OpCode.INT_SUB: OpFormatBinary("-"),
        OpCode.INT_XOR: OpFormatBinary("^"),
        OpCode.INT_ZEXT: OpFormatFunc("zext"),
        OpCode.LOAD: OpFormatSpecial(),
        OpCode.NEW: OpFormatFunc("newobject"),
        OpCode.POPCOUNT: OpFormatFunc("popcount"),
        OpCode.LZCOUNT: OpFormatFunc("lzcount"),
        OpCode.RETURN: OpFormatSpecial(),
        OpCode.STORE: OpFormatSpecial(),
    }

    @classmethod
    def fmt_op(cls, op: PcodeOp) -> str:
        fmt = cls.OP_FORMATS.get(op.opcode, cls.DEFAULT_OP_FORMAT)
        if op.opcode == OpCode.LOAD:
            return fmt.fmt(op)
        return (f"{fmt.fmt_vn(op.output)} = " if op.output else "") + fmt.fmt(op)


def is_pure(x):
    """
    "Pure" instructions only set registers or uniques and have no other side effects
    """


def definite_clobbered(ops):
    """
    Instructions tend to set many tags, which are obviously unused. This is a simple conservative analysis to state which
    instructions are definitely clobbered by a later instruction.
    """
    future_clobber = set()
    clobber_insn = []
    for i, op in enumerate(reversed(ops)):
        """
        print(
             PcodePrettyPrinter.fmt_op(op),
            # [OpFormat.fmt_vn(vn) for vn in future_clobber],
            future_clobber,
            clobber_insn,
        )
        """
        if is_branch(op.opcode):
            future_clobber = set()
        else:
            if op.output != None and OpFormat.fmt_vn(op.output) in future_clobber:
                clobber_insn.append(len(ops) - i - 1)
            else:
                if op.output != None:
                    future_clobber.add(
                        OpFormat.fmt_vn(op.output)
                    )  # any previous write will get clobbers
                future_clobber.difference_update(
                    [OpFormat.fmt_vn(vn) for vn in op.inputs]
                )  # unless needed by intermediate instruction
    return clobber_insn


def uniques(ops):
    vns = defaultdict(set)
    for op in ops:
        if op.output and op.output.space.name == "unique":
            vns[op.output.size].add(op.output)
        for vn in op.inputs:
            if vn.space.name == "unique":
                vns[vn.size].add(vn)
    return vns


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="[%(name)s:%(levelname)s] %(message)s")


def main():
    ap = argparse.ArgumentParser(
        prog="pcode2c.naive",
        description="Disassemble and translate machine code to P-code using SLEIGH. \
            This translation is close to C. Further manual fixups are needed.",
    )
    ap.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="list supported architecture languages",
    )
    ap.add_argument("langid", help="architecture language id")
    ap.add_argument("binary", help="path to flat binary code")
    ap.add_argument("base", default="0", nargs="?", help="base address to load at")
    ap.add_argument(
        "-o", "--offset", default="0", help="offset in binary file to load from"
    )
    ap.add_argument(
        "-s", "--length", default=None, help="length of code in bytes to load"
    )
    ap.add_argument(
        "--clobber",
        action="store_true",
        help="Perform conservative clobber analysis to delete clobbered instructions",
    )
    ap.add_argument(
        "-i",
        "--max-instructions",
        default=0,
        type=int,
        help="maximum number of instructions to translate",
    )
    ap.add_argument(
        "-b",
        "--basic-block",
        action="store_true",
        default=False,
        help="stop translation at end of basic block",
    )

    # List supported languages
    langs = {lang.id: lang for arch in Arch.enumerate() for lang in arch.languages}
    if ("-l" in sys.argv) or ("--list" in sys.argv):
        for langid in sorted(langs):
            print("%-35s - %s" % (langid, langs[langid].description))
        return

    args = ap.parse_args()

    # Get requested language
    if args.langid not in langs:
        print(f'Language "{args.langid}" not found.')
        t = args.langid.upper()
        suggestions = [
            langid
            for langid in langs
            if SequenceMatcher(None, t, langid.split()[0].upper()).ratio() > 0.25
        ]
        if len(suggestions):
            print("\nSuggestions:")
            for langid in sorted(suggestions):
                print("  %-35s - %s" % (langid, langs[langid].description))
            print("")
        print("Try `--list` for full list of architectures.")
        sys.exit(1)

    if args.langid != "x86:LE:64:default":
        print("***** WARNING: Only x86:LE:64:default has been examined")
    # Load target binary code
    base = int(args.base, 0)
    with open(args.binary, "rb") as f:
        f.seek(int(args.offset, 0))
        code = f.read(int(args.length, 0)) if args.length else f.read()

    # Translate
    ctx = Context(langs[args.langid])

    try:
        flags = TranslateFlags.BB_TERMINATING if args.basic_block else 0
        res = ctx.translate(
            code, base, max_instructions=args.max_instructions, flags=flags
        )
        if args.clobber:
            clobber_insn = definite_clobbered(res.ops)
        else:
            clobber_insn = []
        print(f"#include <stdint.h>")
        print(f"#include <stdbool.h>")
        print(f"#include <string.h>")
        if args.langid == "x86:LE:64:default":
            print(
                "extern uint64_t RDI, RSI, RDX, RCX, R8, R9, RAX, RBX, RBP, RSP, RIP;"
            )
            print("extern bool ZF, SF, OF, CF, PF;")
            print("extern uint8_t ram[0x1000];")

        print(f"void asm_{args.offset}(){{")
        for size, vns in uniques(res.ops).items():
            vns = set(OpFormat.fmt_vn(vn) for vn in vns)
            print(f"uint{size*8}_t {', '.join(vns)};")
        last_imark_idx = 0
        for i, op in enumerate(res.ops):
            if i in clobber_insn:
                # print(
                #    f"   // CLOBBERED P{i - last_imark_idx - 1:d}: {PcodePrettyPrinter.fmt_op(op)};"
                # )
                continue
            if op.opcode == OpCode.IMARK:
                last_imark_idx = i
                disas_addr = op.inputs[0].offset
                disas_offset = disas_addr - base
                disas_len = sum(vn.size for vn in op.inputs)
                disas_slice = code[disas_offset : disas_offset + disas_len]
                for insn in ctx.disassemble(disas_slice, disas_addr).instructions:
                    print(
                        f"L{insn.addr.offset:#x}: // {insn.mnem} {insn.body}"  # / len {insn.length}
                    )
            else:
                print(
                    f"   {PcodePrettyPrinter.fmt_op(op)};"  #  // P{i - last_imark_idx - 1:02d}:
                )
        print("}")
    except (BadDataError, UnimplError) as e:
        print(f"An error occurred during translation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
