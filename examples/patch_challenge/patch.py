import patcherex2


proj = patcherex2.Patcherex("a.out")

#     1197:	83 c0 03             	add    $0x3,%eax
addr = 0x1197
code = "add eax, 0x5"
my_patch = patcherex2.ModifyInstructionPatch(addr, code)
proj.patches.append(my_patch)
proj.apply_patches()
proj.binfmt_tool.save_binary("a_patched.out")


code = "x = x + 3;"
