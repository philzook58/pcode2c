# @category: PCode2C
# @toolbar scripts/live.png
# @menupath Pcode2C.liveness
from ghidra.program.model.block import BasicBlockModel

func = getFunctionContaining(currentAddress)
func.getBody()
startAddress = func.getEntryPoint()

listing = currentProgram.getListing()
start_insn = listing.getInstructionAt(startAddress)
# https://ghidra.re/ghidra_docs/api/ghidra/program/database/code/InstructionDB.html

# get all instruction in a function
insns = set([start_insn])
todo = [start_insn]
next = {}
while len(todo) > 0:
    insn = todo.pop()
    fallthrough = insn.getDefaultFallThrough()
    if fallthrough is None:
        next[insn] = set()
    else:
        new_insn = listing.getInstructionAt(fallthrough)
        next[insn] = set([new_insn])
        if new_insn not in insns:
            insns.add(new_insn)
            todo.append(new_insn)
    for addr in list(insn.getFlows()):
        print(addr)
        new_insn = listing.getInstructionAt(addr)
        next[insn].add(new_insn)
        if new_insn in insns:
            continue
        insns.add(new_insn)
        todo.append(new_insn)
# could go in there and find the ret instructions

# prev = [next,insn for insn, nexts in next.items() for next in nexts]
# collect up by


def is_ret(insn):
    for op in insn.getPcode():
        if op.getOpcode() == ghidra.program.model.pcode.PcodeOp.RETURN:
            return True
    return False


print(insns)

# callee saved and return registers are live at end of function

cc = func.getCallingConvention()

cc.getKilledByCallList()
print("trasH", cc.getLikelyTrash())
print("return", cc.getReturnAddress())
print(
    "return loc",
    cc.getReturnLocation(func.getReturnType(), currentProgram),
)  # ghidra.program.model.data.UnsignedLongDataType()
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html#getStorageLocations(ghidra.program.model.listing.Program,ghidra.program.model.data.DataType%5B%5D,boolean)
live_exit = cc.getUnaffectedList()
# this is probably a stack address + cc.getReturnAddress()

print(dir(cc))
live_exit = {
    currentProgram.getRegister(varnode.getAddress(), varnode.getSize())
    for varnode in live_exit
}
live_exit.add(cc.getReturnLocation(func.getReturnType(), currentProgram))
live_out = {insn: set(live_exit) if is_ret(insn) else set() for insn in insns}
live_in = {insn: set() for insn in insns}


print("live_exit", live_exit)
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/OperandType.html#doesRead(int)
uses = {
    insn: {insn.getRegister(i) for i in range(insn.getNumOperands()) if doesRead()}
    for insn in insns
}
defines = {insn: set() for insn in insns}  # todo

for j in range(10):
    for insn in insns:
        for next_insn in next[insn]:
            live_out[insn] |= live_in[next_insn]
        live_in[insn] |= live_out[insn].difference(defines[insn])
        live_in[insn] |= uses[insn]

print("live_in", live_in)
print("live_out", live_out)

for insn in insns:
    insn.getFallFrom()
    insn.getFlows()
    print(insn, "next", insn.getNext())

    insn.getReferenceIteratorTo()

    for i in range(insn.getNumOperands()):
        print("obobjects", insn.getOpObjects(i))
        print("register", insn.getRegister(i))
        print("registervalue", insn.getRegisterValue(insn.getRegister(i)))

# https://gist.github.com/bin2415/15028e78d5cf0c708fe1ab82fc252799
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/block/BasicBlockModel.html
bbModel = BasicBlockModel(currentProgram)
codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), None)
while codeBlockIterator.hasNext():
    bb = codeBlockIterator.next()
    print(bb)
    # bb_set.add(bb.getMinAddress().getOffset())
    # bb_func_set.add(bb)
    # G = addBB(bb, G, bb_func_map)
