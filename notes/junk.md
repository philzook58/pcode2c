refactor to use pypcode
floating point
_Generic switch?
script to dump decompiled from ghidra
dwarf annot

exe:
 $(CC) -g -Wformat=0 -Wimplicit-fallthrough=0 -o harness harness.c

loops:
 cbmc harness.c --show-loops

z3 and boolector hit pretty hard
--sat-solver cadical halves minisat time

--external-sat-solver kissat is about as good as cadical

--show-loops
--no-built-in-assertions
Output little vs big endian into makefile. also arch size
Go through all the warnings. I should be using constant lablled by size.
try enqueue now that carry is fixed.

How we're printing negative constants seems wrong
I should put pc = address _before_ the case.
when Iincrease the unwindig, now the unwinding assertion fails. That is not good. Perhaps this is because

Ok so the new cbmc is way slower.
Try uautomizer / cpachecker. This is it's own longshot

demo breakpoint comparison

speed up via... turn off symex?
try kissat or cadical

malloc is astonishingly faster for allocating blocks of memory in cbmc compared to statically sized arrays. I have no idea way
It does seem like it is working correctly though.
ass #include<astdlib.h> is way slower.... why?

doesn't seem like inline annotations change anytihg much. Maybe 10%? but maybe not

cbmc harness.c --object-bits 10 --unwind 2  --property main.assertion.1 --property main.assertion.2 --unwinding-assertions --boolector

If I could remove all those memcpy checks.

--show-properties
--property main.assertion.1

Ok I'm paying loop cost for printing. I could target the dispatch loop.
Conditional compilation
Remove the prints
Inline the loop there ahead of time.

CBMC_OPTIONS= --bounds-check --conversion-check --div-by-zero-check --float-overflow-check --malloc-fail-null \
 --malloc-may-fail --nan-check --pointer-check --pointer-overflow-check --pointer-primitive-check \
 --signed-overflow-check --undefined-shift-check --unsigned-overflow-check

harness.c:(.text+0x377f): undefined reference to `INT_CARRY'
/usr/bin/ld: harness.c:(.text+0x37bf): undefined reference to`INT_SCARRY'
/usr/bin/ld: harness.c:(.text+0x4a22): undefined reference to `INT_CARRY'
/usr/bin/ld: harness.c:(.text+0x4a59): undefined reference to`INT_SCARRY'
/usr/bin/ld: harness.c:(.text+0x4ef8): undefined reference to `INT_CARRY'
/usr/bin/ld: harness.c:(.text+0x4f3b): undefined reference to`INT_SCARRY'
/usr/bin/ld: /tmp/ccnfoqer.o: in function `main':
harness.c:(.text+0x638d): undefined reference to`FUNCTION'
collect2: error: ld returned 1 exit status

goto-diff
go
--taint in goto-analyzer
Could also have stuff that process opens cbmc with the decompiler stuff?

Hmm. Maybe I could also dump the high pcode output.

values map usage.
<https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/AskValuesExampleScript.java>

echo '
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decompinterface = DecompInterface()
decompinterface.openProgram(currentProgram);
functions = currentProgram.getFunctionManager().getFunctions(True)

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

with open("decompiled_output.c", "w") as output_file:
    for function in list(functions):
        # Add a comment with the name of the function
        # print "// Function: " + str(function)
        output_file.write("// Function: " + str(function))

        # Decompile each function
        decompiled_function = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
        # Print Decompiled Code
        print decompiled_function.getDecompiledFunction().getC()
        #output_file.write(decompiled_function.getDecompiledFunction().getC())
' > /tmp/decompile.py

echo "
int foo(int x){
    return x*x + 1;
}
" > /tmp/foo.c

# huh. ghidra doesn't support dwarf 5? That seems nuts

gcc -gdwarf-4 -c /tmp/foo.c -o /tmp/foo.o

    # Setup decompiler
    # decompInterface = DecompInterface()
    # decompInterface.openProgram(currentProgram)
    # Get the body of the function
    # functionBody = function.getBody()

    # Iterate over all instructions in the function
    # instructions = getCurrentProgram().getListing().getInstructions(functionBody, True)

    # func2c(func)

    # Find the function with the given name
    # functionSymbol = SymbolUtilities.getLabelOrFunctionSymbol(
    #    currentProgram, functionName, None
    # )
    # function = getFunctionContaining(currentProgram.getListing().getCurrentAddress())
    # function = symbolTable.getFunction(functionSymbol.getAddress())

{
    // PUSH RBP
    // 0xdeadbeef
{
    // (unique, 0xef80, 8) COPY (regsiter, 0x28, 8)
    int op1, op2, out;
    memcpy(&op1, state->register + 0x28, 8);
    out = op1;
    memcpy(state->unique + 0xef80, &out, 8);
}

}

void COPY(addr1,addr2, size){
    memcpy(addr1, addr2, size);
}

# define BINOP64(name, operator) void name(out,in1,in2){ }

# define BINOP(name,op,type)  void name(out,in1,in2){ type in1, in2, out; memcpy(&in1, in1, sizeof(type));\

    memcpy(&in2, in2, sizeof(type)); \
    out = in1 operator in2; \
    memcpy(out, out, sizeof(type)); }
We need to
void INT_ADD64(a1,a2,a3){
    int64_t op1, op2, out;
    memcpy(&in1, a1, 64);
    memcpy(&in2, a2, 64);
    memcpy(out, &out, 64);
}

INT_ADD64(register + 0x28, register + 0x30, unique + 0xef80);

INT_ADD(resgiter + , + , )
BINOP(INT_ADD);

}

    # Iterate through each basic block in the function
    for block in function.getBasicBlocks():
        for inst in block.getInstructions(True):
            # Get the high-level representation (HighFunction) for decompilation
            #highFunction = decompInterface.decompileFunction(
            #    function, 0, ConsoleTaskMonitor()
            #)
            #if highFunction is None or not highFunction.decompileCompleted():
            #    print("Decompilation error")
            #    continue

            # Get the p-code for each instruction
            pcodeOps = highFunction.getPcodeOps(inst.getAddress())
            for op in pcodeOps:
                # Process based on the type of p-code operation
                if op.getOpcode() == PcodeOp.COPY:
                    print("COPY operation at", op.getAddress())
                elif op.getOpcode() == PcodeOp.LOAD:
                    print("LOAD operation at", op.getAddress())
                elif op.getOpcode() == PcodeOp.STORE:
                    print("STORE operation at", op.getAddress())
                # Add more elif statements for different p-code operations as needed
                else:
                    print("Other operation at", op.getAddress())

<https://github.com/niconaus/pcode-interpreter/blob/main/Interpreter.hs>

    assert numInputs <= 3
    if numInputs == 1:
        x = interp_varnode(pcode.getInput(0))
        print(x)
        
        
    if pcode.getNumInputs() > 1:
        y = interp_varnode(pcode.getInput(1))
    if pcode.getNumInputs() > 2:
        z = interp_varnode(pcode.getInput(1))
    # Process based on the type of p-code operation
    if op == PcodeOp.COPY:
        return "state->mem[%d] = state->;" % (pcode.getAddress())
        print("COPY operation at", op.getAddress())
    elif op == PcodeOp.LOAD:
        print("LOAD operation at", op.getAddress())
    elif op == PcodeOp.STORE:
        print("STORE operation at", op.getAddress())
    # Add more elif statements for different p-code operations as needed
    else:
        print("Other operation at", op.getAddress())


    if pcode.isAssignment():
        if op == pcode.BOOL_AND:
            e = "&"
        elif op == pcode.BOOL_NEGATE:
            e = "!" # Hmm. Is this what we want?
        elif op == pcode.BOOL_OR:
            e = "|"
        elif op == pcode.BOOL_XOR:
            e = "^"
        elif op == pcode.COPY:
            e = x
        elif op == pcode.INT_ADD:
            e = "+"
            signed = True
        elif op == pcode.INT_AND:
            e = "&"
            signed = True
        elif op == pcode.INT_SUB:
            e = "-"
            signed = True
        elif op == pcode.INT_DIV:
            e = "/"
            signed = True
        elif op == pcode.INT_EQUAL:
            e = "=="
        elif op == pcode.INT_LEFT:
            e = "<<"
        elif op == pcode.INT_LESS:
            e = "<" 
        elif op == pcode.INT_MULT:
            e = "*"
        elif op == pcode.INT_NOTEQUAL:
            e = x != y
        elif op == pcode.INT_SBORROW:
            # revisit this one. I'm confused why this is different
            # from SLESS
            e = x > y
        elif op == pcode.INT_SEXT:
            outsize = pcode.getOutput().getSize()
            insize = pcode.getInput(0).getSize()
            e = Function("(_ sign_extend %d)" % (outsize - insize), [x])
        elif op == pcode.INT_SLESS:
            e = bvslt(x, y)
        elif op == pcode.INT_SUB:
            e = x - y
        elif op == pcode.INT_ZEXT:
            outsize = pcode.getOutput().getSize()
            insize = pcode.getInput(0).getSize()
            e = Function("(_ zero_extend %d)" % (outsize - insize), [x]) 
        elif op == pcode.INT_ZEXT:
            outsize = pcode.getOutput().getSize()
            insize = pcode.getInput(0).getSize()
            e = Function("(_ zero_extend %d)" % (outsize - insize), [x]) 
        elif op == pcode.LOAD:
            e = get_mem(x, y)
        elif op == pcode.POPCOUNT:
            e = Function("popcount", [x])
        elif op == pcode.SUBPIECE:
            # I always have a hard time getting extract right
            # in principal this offset might be symbolic? Hmm.
            size = pcode.getInput(1).getOffset() - 1
            e = Function("(extract _ %d 0)" % size ,[x])
        else:
            print "missing opcode"
            print pcode
            assert False
        #out = interp_varnode(pcode.getOutput())
        out = pcode.getOutput()
        space = bvconst(out.getSpace(), 64)
        offset = bvconst(out.getOffset(), 64)
        s = Comment(str(pcode),
        #Let([(out, e)], post))
        Let([(Mem, store(Mem, space, offset, e))], post))
        return s
    elif op == pcode.STORE:
        return Comment(str(pcode), Let([Mem], store(Mem, x, y, z)))
    elif op == pcode.BRANCH:
        print "WARN: branch unimplemented"
        return post
    elif op == pcode.CBRANCH:
        print "WARN: cbranch unimplemented"
        return post
    elif op == pcode.RETURN:
        print "WARN: return unimplemented"
        return post
    else:
        print pcode
        assert False
