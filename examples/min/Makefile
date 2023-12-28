# if boolector is intalled, it is reccommended.

# You may need to increase the address bit size
# --object-bits 10 

# --compact-trace

# Picking a particular property to check
# --show-properties
# --property main.assertion.1

UNWIND=4

# Other useful options. See CBMC manual for more information
CBMC_OPTIONS= --bounds-check --conversion-check --div-by-zero-check --float-overflow-check --malloc-fail-null \
	--malloc-may-fail --nan-check --pointer-check --pointer-overflow-check --pointer-primitive-check \
	--signed-overflow-check --undefined-shift-check --unsigned-overflow-check

cbmc:
	cbmc harness.c --unwinding-assertions --unwind $(UNWIND)