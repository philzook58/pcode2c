HARNESS=verify.c

# Large amounts of unwinding are slower
# Too few is unsound (--unwinding-assetion will fail)
# set unwind to approximately number of basic blocks in longest execution path
UNWIND=3

# Obviously some assumptions need to be revisited for other architectures
ENDIAN=--little-endian
ARCH=x86_64

# You may need to increase the address bit size. CBMC will throw an error saying so if needed.
OBJECT_BITS=13

# Picking a particular property to check
# --property main.assertion.1
CC=gcc

# Other useful options. See CBMC manual for more information
CBMC_OPTIONS=
#CBMC_OPTIONS+= --trace                       # for counterexample traces
#CBMC_OPTIONS+=--show-properties              # to lookup and turn on only specific properties. Can increase speed
#CBMC_OPTIONS+=--show-loops                   # To lookup loop names for unwinding specific loops
CBMC_OPTIONS+=--no-built-in-assertions
#CBMC_OPTIONS+=--property main.assertion.1    # Picking a particular property to check
#CBMC_OPTIONS+= --bounds-check --conversion-check --div-by-zero-check --float-overflow-check --malloc-fail-null \
#	--malloc-may-fail --nan-check --pointer-check --pointer-overflow-check --pointer-primitive-check \
#	--signed-overflow-check --undefined-shift-check --unsigned-overflow-check

# Some alternative solver options to consider. YMMV.
#SOLVER=--z3
#SOLVER=--sat-solver cadical
#SOLVER=--boolector
#SOLVER=--ext-sat-solver kissat

cbmc:
	cbmc $(HARNESS) --unwinding-assertions --object-bits $(OBJECT_BITS) \
	--unwind $(UNWIND) $(ENDIAN) --arch $(ARCH) $(SOLVER) $(CBMC_OPTIONS) \
	--graphml-witness witness.graphml

exe:
	$(CC) -o verify (HARNESS)