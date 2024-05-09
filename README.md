# pcode2c

WIP: Do not expect this to work for you yet.

pcode2c is a Ghidra translator script from low pcode to a [specialized C interpreter](https://www.gtoal.com/sbt/) for the purposes of running the resulting code through off the shelf verifiers (for example [CBMC](https://github.com/diffblue/cbmc)). The resulting C has a direct mapping to the underlying assembly.

C is a useful intermediate because it enables using powerful off the shelf verifiers and can be directly compared (with a little muscle grease) against decompilaton or source.

This enables soundly answering questions about the relationship between high level source and binary in a relatively easy manner that no other method I know of can do.

Blog posts:
- <https://www.philipzucker.com/pcode2c/>
- [DWARF Verification via Ghidra and CBMC](https://www.philipzucker.com/pcode2c-dwarf/
## Installation

```bash
python3 -m pip install -e .
```

## Usage

```bash
python3 -m pcode2c ./examples/min/mymin.o > tmp.c
gcc -I _templates -c tmp.c 
```

## Ghidra Plugin Installation

- Open up Ghidra on a binary
- Click on `Window > Script Manager` in the toolbar
- Manage Script Directories button in top right of Script Manager window (looks like a checklist)
- Find the `./scripts` directory and add it
- Click Refresh Script List in script manager
- There is now a PCode2C folder in the script manager. Go to it and click

## Example
