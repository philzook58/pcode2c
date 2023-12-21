# @category: PCode2C
# @toolbar icon.gif
# @menupath Pcode2C.run

# Import Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
import sys
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolUtilities


def interp_varnode(varnode):
    size = varnode.getSize()
    if size == 1:
        typ = "int8_t"
    elif size == 2:
        typ = "int16_t"
    elif size == 4:
        typ = "int32_t"
    elif size == 8:
        typ = "int64_t"
    else:
        assert False, "unrecognized size %d" % size
    space = varnode.getSpace()
    offset = varnode.getOffset()
    size = str(varnode.getSize())
    # check if in constant map
    # also probably reg map
    # print(dir(space))
    if varnode.isConstant():
        return "&({}){{{}}}".format(typ, hex(varnode.getOffset())), size
    elif varnode.isRegister():
        reg = currentProgram.getRegister(varnode.getAddress(), varnode.getSize())
        if reg != None:
            name = reg.getName()
        return "reg + 0x{:x} /* {} */".format(varnode.getOffset(), name), size
    elif varnode.isUnique():
        return "unique + 0x{:x}".format(varnode.getOffset()), size
    elif varnode.isAddress():
        return "ram + 0x{:x}".format(varnode.getOffset()), size
    # addrspace = currentProgram.getAddressFactory().getAddressSpace(varnode.getOffset())
    # name += addrspace.getName()
    else:
        assert False, "unrecognized varnode type {}".format(varnode)


def pcode2c(pcode):
    # print(dir(pcode))
    numInputs = pcode.getNumInputs()
    args = list(pcode.getInputs())
    output = pcode.getOutput()
    if output != None:
        args = [output] + args
    args = map(interp_varnode, args)
    args = sum(args, ())
    args = ", ".join(args)
    return "\t{}({}); // {}".format(pcode.getMnemonic(), args, pcode)


def block2c(block):
    for inst in block.getInstructions(True):
        print(inst)
        pcodeOps = highFunction.getPcodeOps(inst.getAddress())
        for op in pcodeOps:
            pcode2c(op)


def func2c(func):
    currentProgram = getCurrentProgram()
    blockModel = BasicBlockModel(currentProgram)
    monitor = ConsoleTaskMonitor()
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)
    for block in blocks:
        block2c(block)


def dump_raw_pcode(func):
    func_body = func.getBody()
    listing = currentProgram.getListing()
    opiter = listing.getInstructions(func_body, True)
    output = []
    output.append('#include "pcode.h"')
    output.append("void {}(CPUState *state){{".format(func.getName()))
    output.append(
        "uint8_t* reg = state->reg; uint8_t* unique = state->unique; uint8_t* ram = state->ram;"
    )
    output.append("for(;;){")
    output.append("switch(state->pc) {")
    while opiter.hasNext():
        op = opiter.next()
        output.append("case 0x{}:".format(op.getAddress()))
        output.append("// {}".format(op))
        raw_pcode = op.getPcode()
        for entry in raw_pcode:
            output.append(pcode2c(entry))
    output.append("default: assert(0);")
    output.append("}}}")
    return "\n".join(output)


if __name__ == "__main__":
    # Get current program and function
    currentProgram = getCurrentProgram()
    symbolTable = currentProgram.getSymbolTable()
    # Get function name from command line arguments

    args = getScriptArgs()
    print(args)
    if len(args) > 0:
        funcName = args[0]  # sys.argv[1]
        func = getGlobalFunctions(funcName)[0]
    else:
        func = getFunctionContaining(currentAddress)

    output = dump_raw_pcode(func)
    print(output)
    with open("/home/philip/Documents/python/pcode2c/decomp.c", "w") as f:
        f.write(output)
