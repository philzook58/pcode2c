# @category: PCode2C
# @toolbar scripts/C_Logo.png
# @menupath Pcode2C.run

import subprocess


func = getFunctionContaining(currentAddress)
funcname = func.getName()

startAddress = func.getEntryPoint()

endAddress = func.getBody().getMaxAddress()
listing = currentProgram.getListing()
insn = listing.getInstructionAt(endAddress)
endAddress = endAddress.add(insn.getLength())

language = currentProgram.getLanguageCompilerSpecPair()
filename = currentProgram.getExecutablePath()

values = ghidra.features.base.values.GhidraValuesMap()
values.defineFile("Bin File", java.io.File(filename))  # get current file
values.defineAddress("Start Address", startAddress, currentProgram)
values.defineAddress("End Address", endAddress, currentProgram)
# values.defineFile(
#    "Out File", java.io.File(filename + ".pcode2c." + funcname + ".c")
# )  # get current file
values.defineLanguage("Language", language)
values = askValues("Pcode2C", None, values)
command = [
    "python3",
    "-m",
    "pcode2c",
    str(values.getFile("Bin File")),
    "-b",
    str(values.getLanguage("Language").getLanguageID()),
    "--start-address",
    str(values.getAddress("Start Address")),
    "--end-address",
    str(values.getAddress("End Address")),
]
print(command)

proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Poll process for new output until finished
while True:
    # Try to read from stdout
    output = proc.stdout.readline()
    if output:
        print(output.rstrip())

    # Try to read from stderr
    err = proc.stderr.readline()
    if err:
        print(err.rstrip())

    # Check if process has terminated
    if proc.poll() is not None:
        break

# Make sure we read any remaining output after the process has finished
for output in proc.stdout.readlines():
    print(output.rstrip())
for err in proc.stderr.readlines():
    print(err.rstrip())

# Close subprocess' file descriptors
proc.stdout.close()
proc.stderr.close()
