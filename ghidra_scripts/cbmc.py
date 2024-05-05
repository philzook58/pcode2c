# @category: PCode2C
# @toolbar cbmc.png
# @menupath Pcode2C.cbmc

from ghidra.app.decompiler import DecompInterface

def get_c_code() -> str:
    """
    if cfile is not provided run_cbmc will use this instead
    putting this content into a tmp file
    """
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    func = getFunctionContaining(currentAddress)
    res = decomp.decompileFunction(func, 0, None)
    ccode = res.getDecompiledFunction().getC()
    return ccode

def values_setup():
    """
    setup ghidra values map
    """
    values = ghidra.features.base.values.GhidraValuesMap()

    values.defineFile("C File (default is decompiler)", java.io.File(""))
    values.defineInt("Unwind", 1)
    values.defineInt("Object Bits", 8)
    values.defineChoice("Solver", "default", "default", "smt2", "boolector")
    values.defineString(
        "Options",
        "--trace --bounds-check --conversion-check --div-by-zero-check --float-overflow-check --malloc-fail-null \
        --malloc-may-fail --nan-check --pointer-check --pointer-overflow-check --pointer-primitive-check \
        --signed-overflow-check --undefined-shift-check --unsigned-overflow-check --memory-leak-check",
    )
    values.defineString("Function", getFunctionContaining(currentAddress).getName())

    values = askValues("Model Check C File with CBMC", None, values)
    return values

def get_c_file(values) -> str:
    """
    either get the C file from values or from get_c_code
    """
    cfile = values.getFile("C File (default is decompiler)")
    if cfile is None:
        ccode = get_c_code()
        print("Writing decompiled code to /tmp/decomp.c:")
        print(ccode)
        filename = "/tmp/decomp.c"
        with open(filename, "w") as f:
            f.write(ccode)
        cfile = filename
    else:
        cfile = str(cfile)

    return cfile

def run_cbmc() -> None:
    """
    run cbmc with arguments specified by values_setup and get_c_file
    """
    values = values_setup()

    cfile = get_c_file(values)

    # TODO get arch, get bits, get endianess
    command = [
        "cbmc",
        cfile,
        "--unwind",
        str(values.getInt("Unwind")),
        "--object-bits",
        str(values.getInt("Object Bits")),
        "--function",
        values.getString("Function"),
        "--unwinding-assertions",
    ] + values.getString("Options").split()

    solver = values.getChoice("Solver")
    if solver != "default":
        command.append("--" + solver)

    print("Running command: `" + " ".join(command) + "`")

    import subprocess
    import sys

    # Start the subprocess with stdout and stderr piped
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


if __name__ == "__main__":
    run_cbmc()
