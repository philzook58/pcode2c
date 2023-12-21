# Static Binary Translation for Verification

pcode2c is a translator from low pcode to C for the purposes of running the resulting code through off the shelf verifiers. The resulting C has a direct mapping to the underlying assembly.

C is a useful intermediate because it enables using powerful off the shelf verifiers and can be directly compared (with a little muscle grease) against decompilaton or source.

This enables soundly answering questions about the relationship between high level source and binary in a relatively easy manner that no other method I know of can do.

Also it is a method to ask questions about just the binary behavior.

# Why Binary Verification?

Binaries are a thin pipe. There is a huge pile of hardware stuff underneath, and a tremendous toplng tower of languages and software above.

There is a long history of wanting to translate binaries from one ISA to another (cifuentes). There are an number of approaches.
Really, one wants to work in a portable higher level language in the first place. This is not always a silver bullet.

There are a number of reasons to perform binary translation.

Why do we want to verify at the binary level

1. High Low Correspondence Recovery. Optimizing compiler by design mangle your code as much as is fruitful during the translation to assembly. This makes the correspondence of CPU state and high level state difficult to pin down except at agreed locations such as function entry and exit (These sorts of things are referred to as the ABI). The interior of functions is often a bit vague _exactly_ how the high code corresponds to the low code.
This information is possibly usefl for a couple use cases.
1. Smaller verification chunks / more verification targets
2. Better Debug Data
3. Post Hoc Patchability (microlinking). In principle one could seriously reduce compile times. Similar to how separate compilation and linking allows one to limit the amount of recompilation one has to do. One ould imagine microlinking or dynamic microlinking/patching.
4. More precise decompilation

If you need to connect the hgh code to the low code, you need them to somehow be in the same system.

5. Compiler Validation.
6. Decompiler Validation
7. Binary Verification

There are more frameworks for higher level language verification. The options for assembly are more limited.

## Interpret, JIT, or Decompile

In principle, writing an interpreter for assembly is laborious but straightforward. You can for example find many smple emulators on the internet for gameboys. A straight interpreter is perceived as being too slow for many applications.
Another approach that has been sucessful is dynamic binary translation like QEMU. In this case, the recovery of control flow is done by executing the program and having a fast JIT engine to translate to the host arhchitecture.

The basic state of a CPU is the value in it's registers (including the program counter), and the values in memory. You can make a data structure representing this. Then some kind of looping dispatch (while + switch) on the current address pointed to PC and do the operatons that instruction specifies.

We can specialize this interpreter to a particular sequence of instructions. We don't need to necessarily dispatch back to the switch statement if we statically know where execution will go next.

Typical decompilation takes a further step of noting that lots of things the cpu is doing are statically recognizable as unnecssary and control flow can be simplified further.

Decompilers are a known entity and very useful for human reverse engineers to naviagte their way around a binary.

Decompilation can be perceived as trying to recover something similar to the original source.

Recompilable decompilation is decompilation that can be thrown into gcc and produce a new binary. This sounds great, but is very challenging.

## Why C?

There are a couple of advantages of using C as an IR to verifiers.

1. Lots of work has been invested. Can use preeexistig verifiers, linters, knwon problems.
2. It can be compiled and run. Fuzzing can be a good sanity check that all tghe pieces are working as expected.
3. It is comprehensible and familiar to engineers. Building a new language is a lot of work and learning this language is also. Most languages fail.

C is of course not ideal in that it has some peculair semantics. Some of this is historical baggage, some is defined to enable compiler optimizations, which is not useful here. The semantics of an add instruction are not up for as much debate as the semantics of the C addition operator.
The processor does _something_ when an integer overflows. In C, what "happens" on overflow is more subtle.

In any case it is worth a shot.

Off the shelf C automated verification is underutilized. It is quite nice and very powerful.

## Is Verification Worthwhile?

No.
This is why software verification is kind of a backwater. It delivers second or third order value.
Compilers are intended to produce correct code. They are imperfect, fine. So is the world.

But it is kind of a fun.

What is good? Happiness, lives, and money.
In the sense the subject is intrinsically beuatiful it increases happiness.
Money in the software world translates to requiring fewer or cheaper salaries, or less bugs for which you are financially liable. Ransomware. For very expensive physical systems, making sure they don't blow up because of some dumb bug is good

Lives is worrying. This is the critical systems (planes, rockets, automated vehicles) or defense or medical devices.

Probably the most value is not the verification persay, but having someone smart enough to do something akin to verification pour over your system.

Having said that, testing is good because it is an automatic form of sanity checking. mployees come and go and we all oly have so much brain space or attention span.

## Why Ghidra?

Ghidra is a remarkable entity. It is a decompiler with around 20 years of history and government funding by the NSA. It is not going anywhere.

PCode is ghidra's intermediate representation. It is a smaller target than QEMU or VEX, which are designed for dynamic binary translation. They have more constructs in their IR in order to support more efficient translations. Whereas PCode's main purpose is static analysis/decompilation, not necessarily execution speed.

You have a choice of getting your semabtics of your intructions from already existing sources or go your own way. Building these semantics is a lot of bulk work.

## CBMC

CBMC is a powerful bounded model checker for C. It does have a lower level IR called GOTO, but using this as a target would lock us in, lose familiarity, lose compilability.
There are significant C projects that use CBMC to check conditions

ESBMC is a comparable fork of CBMC.
CBMC can be used to both check for generic problems (use after free, buffer overflow, etc) and also check for user designated properties.
Setting these up is quite similar to setting up a unit test harness or fuzzing harness, except there is a better argument for completeness.
CBMC can also generate unrolling assumption checks that will show that despte the bounded nature of it's loop unrolling, it has covered every possible execution path.
