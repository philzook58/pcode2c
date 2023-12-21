# @category: PCode2C
# @toolbar icon.gif
# @menupath Pcode2C.cbmc

import subprocess


def dump_func(func):
    decompInterface = DecompInterface()
    decompInterface.openProgram(currentProgram)
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high.getCCode()


func = currentFunction()

ccode = dump_func(func)

funcname = func.getName()
filename = "/tmp/decomp.c"
with open(filename, "r") as f:
    f.write(ccode)
subprocess.call(
    ["cbmc", "--function", funcname, filename]
)  # and then all the nice checks
