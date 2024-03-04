# @category: PCode2C
# @toolbar patcherex2.jpeg
# @menupath Pcode2C.patcherex_insert

import subprocess

values = ghidra.features.base.values.GhidraValuesMap()

values.defineAddress("Address", currentAddress, currentProgram)
values.defineString("Assembly", "")
values.defineFile(
    "Outfile", java.io.File(currentProgram.getExecutablePath() + ".patched")
)
# values.defineChoice("Patch Type", "Insert", "Insert", "Modify", "Remove")

values = askValues("Insert Assembly with Patcherex2", None, values)

# Obviously this is unsafe to untrusted users. Escaping attacks are very possible.
prog = """\
import patcherex2
proj = patcherex2.Patcherex("{binfile}")
print("Patching binary at address {addr} with assembly `{assembly}`")
proj.patches.append(patcherex2.InsertInstructionPatch(0x{addr}, "{assembly}", force_insert=True))
proj.apply_patches()
proj.binfmt_tool.save_binary("{outfile}")
print("Patched binary saved to {outfile}")
""".format(
    assembly=values.getString("Assembly"),
    addr=values.getAddress("Address"),
    binfile=currentProgram.getExecutablePath(),
    outfile=values.getFile("Outfile"),
)

print("Running Script:")
print(prog)
command = ["python3", "-c", prog]


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
