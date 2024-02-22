# @category: PCode2C
# @toolbar icon.gif
# @menupath Pcode2C.e9patch

# call e9patch
# ghidra script

import subprocess

values = ghidra.features.base.values.GhidraValuesMap()

"""
values.defineString("Name")
values.defineInt("Count")
values.defineInt("Max Results", 100)
values.defineChoice("Priority", "Low", "Low", "Medium", "High")
values.defineProgram("Other Program")
values.defineProjectFile("Project File")
values.defineProjectFolder("Project Folder")
"""
values.defineAddress("Address", currentAddress, currentProgram)
values.defineString("In Vars", "int foo, int bar")
values.defineString("PatchCode", "int patchCode() {}n\n\n\n\n\n\n\n\n")
values.defineString("Patch Command", "after validateCommand(rax)@goodpatch")
values.defineFile("PatchFile", None)  # java.io.File("patch_code.c"))
values.defineFile("Outfile", java.io.File("patched.bin"))
values = askValues("Patch", None, values)

# check if both PatchFile and patchcode are set

"""
print(values.getString("Name"))
print(values.getInt("Count"))
print(values.getInt("Max Results"))
print(values.getChoice("Priority"))
"""

addr = values.getInt("Address")
outfile = values.getFile("Outfile")


patchcode = values.getString("PatchCode")
with open("/tmp/patch_code.c", "w") as f:
    f.write(patchcode)

res = subprocess.check_output(["e9compile", "/tmp/patch_code.c"])


def command():
    return ["e9patch", "-o", outfile, str(addr)]


command = [
    "e9tool",
    "-M",
    "-Os",
    "--static-loader",
    "'addr == {}'".format(hex(currentAddress)),
    "-P",
    values.getString("PatchCommand"),
    "-o",
    str(values.getFile("Outfile")),
]

res = subprocess.check_output(["e9tool", "--help"])
print(res)

# options = currentProgram.getOptions(currentProgram.PROGRAM_INFO)
# options.getString("foo", None)


"""
separate commands:
Inspect Patches
Perfrom Patch
Add patch
Delete patch


Patcherex2 backend vs e9patch

"""
