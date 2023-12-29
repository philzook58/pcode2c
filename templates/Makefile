# Large amounts of unwinding are slower
# Too few is unsound (--unwinding-assetion will fail)
# set unwind to approximately number of basic blocks in longest execution path
UNWIND=2

ENDIAN=--little-endian
ARCH=--x86_64

# if boolector is intalled, it is reccommended.
# CBMC_OPTIONS += --boolector

# You may need to increase the address bit size
# --object-bits 10 
OBJECT_BITS=10

# --compact-trace

# Picking a particular property to check
# --show-properties
# --property main.assertion.1



# Other useful options. See CBMC manual for more information
CBMC_OPTIONS= --bounds-check --conversion-check --div-by-zero-check --float-overflow-check --malloc-fail-null \
	--malloc-may-fail --nan-check --pointer-check --pointer-overflow-check --pointer-primitive-check \
	--signed-overflow-check --undefined-shift-check --unsigned-overflow-check

cbmc:
	cbmc harness.c --unwinding-assertions --object-bits $(OBJECT_BITS) --unwind $(UNWIND) $(ENDIAN) $(ARCH)