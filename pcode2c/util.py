import subprocess
import tempfile
from elftools.elf.elffile import ELFFile


# Also consider looking here https://docs.pwntools.com/en/stable/asm.html
def asm(code) -> bytes:
    """
    put this code into a temporary file, gcc and provide the contents of the resulting .out file
    """
    with tempfile.NamedTemporaryFile(suffix=".s") as f:
        f.write(code.encode("utf-8"))
        f.flush()
        binfile = f.name + ".out"
        subprocess.run(["gcc", "-nostdlib", "-o", binfile, f.name])
        with open(binfile, "rb") as f:
            return f.read()


# TODO
def infer_address(filename):
    """
    infer file offset, address, size.
    """
    with open(filename, "rb") as file:
        elffile = ELFFile(file)

        # Get the symbol table
        # if args.function is not None:
        #    symtab = elffile.get_section_by_name(".symtab")
        # Search for the function in the symbol table
        #    for symbol in symtab.iter_symbols():
        #        if symbol.name == args.function:
        #            fun_addr = symbol["st_value"]
        e_type = elffile.header["e_type"]
        if e_type == "ET_EXEC" or e_type == "ET_DYN":
            for segment in elffile.iter_segments():
                if segment["p_flags"] & 0x1:  # PF_X flag is 1
                    offset = segment["p_offset"]
                    base = segment["p_vaddr"]
                    size = segment["p_memsz"]
                    break
        else:
            raise ValueError("Unknown ELF type")
        if size == 0:
            raise ValueError("No code found")
        """
        elif e_type == "ET_DYN":
            # Iterate over sections and find the .text section
            for section in elffile.iter_sections():
                if section.name == ".text":
                    offset = section.header["sh_offset"]
                    size = section.header["sh_size"]
                    base = 0
                    break
        """

        if start_address is not None and end_address is not None:
            read_offset = start_address - base + offset
            read_size = min(end_address - start_address, size)
            base = start_address
        else:
            read_offset = offset
            read_size = size

        if read_offset < 0 or read_offset > offset + size:
            print(size)
            print(read_offset)
            print(hex(end_address))
            print(hex(start_address))
            print(hex(base))
            if 0x00100000 <= start_address:
                raise ValueError(
                    "Bad start address (try removing Ghidra 0x00100000 offset)",
                    hex(start_address),
                )
            raise ValueError("Bad start address", hex(start_address))
