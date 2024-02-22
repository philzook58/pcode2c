# @category: PCode2C
# @toolbar scripts/live.png
# @menupath Pcode2C.liveness2

#TODO Add User Code Here
from pprint import pprint
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
func = getFunctionContaining(currentAddress)
print(currentAddress)
print(func)
res = decomp.decompileFunction(func, 0, None)
hf = res.getHighFunction()
blocks = hf.getBasicBlocks()


# def live_at_addr(blocks, addr):
livein = {b.getStart() : set() for b in blocks}

live_at_patch = None
for i in range(len(blocks)): # is this enough iterations? worst case is straight line graph?
    for blk in blocks:
	blk_id = blk.getStart()
        live = set() #copy(liveout[blk_id])
        for outind in range(blk.getOutSize()):
            succblk = blk.getOut(outind)
            live.update(livein[succblk.getStart()]) 
        for pcode in reversed(list(blk.getIterator())):
	    if pcode.isAssignment:
            	live.discard(pcode.getOutput())
	    opcode = pcode.getOpcode()
	    if opcode == pcode.BRANCH:
		pass
            elif opcode == pcode.CBRANCH:
		live.add(pcode.getInput(1))
	    else:
		print(pcode.getOpcode(), pcode.BRANCH)
            	live.update(pcode.getInputs())
	    if pcode.getSeqnum().getTarget() == currentAddress:
	    	live_at_patch =  {v for v in live if not v.isConstant()}
        livein[blk_id] = live
livein = {k : {v for v in vars if not v.isConstant()} for k,vars in livein.items()}
pprint([(blk, [(pcode.getSeqnum(), pcode) for pcode in blk.getIterator()]) for blk in blocks])
pprint(livein)

pprint(currentAddress)
print("live at patch", [(v, v.getHigh().getName()) for v in live_at_patch])


# def live_at_addr(blocks, addr):
avail_out = {b.getStart() : set() for b in blocks}

avail_at_patch = None
for i in range(len(blocks)): # is this enough iterations? worst case is straight line graph?
    for blk in blocks:
	blk_id = blk.getStart()
	avail = {}
	#if blk.getSize() == 0:
       	#	available = set() #copy(liveout[blk_id])
        '''for ind in range(blk.getInSize()):
            prevblk = blk.getIn(ind)
	    if available = None:
		available = {v for v in available_out[prevblk.getStart()])}
	    else:
            	available.intersect_update(available_out[prevblk.getStart()]) 
	'''
        for pcode in blk.getIterator():
		out = pcode.getOutput()
		if out != None:
            		highvar = out.getHigh()
			if highvar != None:
				avail[highvar.getName()] = out
	    		if pcode.getSeqnum().getTarget() == currentAddress:
	    			avail_at_patch =  {k : v for k,v in avail.items()}
        avail_out[blk_id] = avail


print("avail at patch", avail_at_patch)