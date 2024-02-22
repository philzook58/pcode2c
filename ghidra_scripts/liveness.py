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

insns = set([start_insn])
todo = [start_insn]
while len(todo) > 0:
    insn = todo.pop()
    fallthrough = insn.getDefaultFallThrough()
    if fallthrough is not None:
        new_insn = listing.getInstructionAt(fallthrough)
        if new_insn not in insns:
            insns.add(new_insn)
            todo.append(new_insn)
    for addr in list(insn.getFlows()):
        print(addr)
        new_insn = listing.getInstructionAt(addr)
        if new_insn in insns:
            continue
        insns.add(new_insn)
        todo.append(new_insn)
# could go in there and find the ret instructions


def is_ret(insn):
    for op in insn.getPcode():
        if op.getOpcode() == ghidra.program.model.pcode.PcodeOp.RETURN:
            return True
    return False


print(insns)

cc = func.getCallingConvention()

cc.getKilledByCallList()
cc.getLikelyTrash()
cc.getReturnAddress()
live = cc.getUnaffectedList() + cc.getReturnAddress()
live = {insn: set() if is_ret(insn) else set(live) for insn in insns}


insn.getFallFrom()
insn.getFlows()
print(insn.getNext())


insn.getReferenceIteratorTo()

for i in range(insn.getNumOperands()):
    print(insn.getOpObjects(i))
    print(insn.getRegister(i))
    print(insn.getRegisterValue(insn.getRegister(i)))

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
