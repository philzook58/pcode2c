# @category: PCode2C
# @toolbar Ghidra_Logo.png
# @menupath Pcode2C.pcode2c

import subprocess
from ghidra.features.base.values import GhidraValuesMap


def run_pcode2c():
    func = getFunctionContaining(currentAddress)

    startAddress = func.getEntryPoint()

    endAddress = func.getBody().getMaxAddress()
    listing = currentProgram.getListing()
    insn = listing.getInstructionContaining(endAddress)
    endAddress = endAddress.add(insn.getLength())
    size = endAddress.subtract(startAddress)

    memory = currentProgram.getMemory()
    block = memory.getBlock(startAddress)
    mb_source_info = block.getSourceInfos()[0]
    if block and block.getStart().getOffset() != 0:
        file_offset = (
            startAddress.getOffset()
            - block.getStart().getOffset()
            + mb_source_info.getFileBytesOffset()
        )
    else:
        file_offset = None

    language = currentProgram.getLanguageCompilerSpecPair()
    filename = currentProgram.getExecutablePath()
    print(hex(file_offset))
    values = ghidra.features.base.values.GhidraValuesMap()
    values.defineFile("Bin File", java.io.File(filename))  # get current file
    values.defineAddress("Start Address", startAddress, currentProgram)
    values.defineInt("File Offset", file_offset)
    # values.defineAddress("End Address", endAddress, currentProgram)
    values.defineInt("Size", size)
    # values.defineFile(
    #    "Out File", java.io.File(filename + ".pcode2c." + funcname + ".c")
    # )  # get current file
    values.defineLanguage("Language", language)
    import random

    # Super hacky way to get it to clear itself 9 times uot of 10
    # Ghidra is caching the askvules based on the title
    _ = askValues("Pcode2C" + " " * random.randint(100, 200), None, values)
    command = [
        "python3",
        "-m",
        "pcode2c",
        str(values.getFile("Bin File")),
        "-b",
        str(values.getLanguage("Language").getLanguageID()),
        "--start-address",
        "0x" + str(values.getAddress("Start Address")),
        "--file-offset",
        str(hex(values.getInt("File Offset"))),
        "--size",
        str(hex(values.getInt("Size"))),
        # "--end-address",
        # str(values.getAddress("End Address")),
    ]
    del values
    print(command)

    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Poll process for new output until finished
    code = []
    while True:
        # Try to read from stdout
        output = proc.stdout.readline()
        if output:
            print(output.rstrip())
            code.append(output)

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
        code.append(output)
    for err in proc.stderr.readlines():
        print(err.rstrip())

    # Close subprocess' file descriptors
    proc.stdout.close()
    proc.stderr.close()
    return code


if __name__ == "__main__":
    run_pcode2c()
