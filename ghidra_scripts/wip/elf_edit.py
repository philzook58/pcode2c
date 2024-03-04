# @category: PCode2C
# @toolbar scripts/elf.png
# @menupath Pcode2C.elf

# Get elf data
# get current address
# fill out values box with data. Why is it not being updated?

# Use hex writing api

listing = currentProgram.getListing()

# Get the Data object at the current address
phdrarr = listing.getDataBefore(currentAddress)
phdr = phdrarr.getComponentContaining(currentAddress.subtract(phdrarr.getAddress()))
phdr = phdr.getDataType()
for comp in phdr.getComponents():
    print(comp)

"""
if data_at_address is not None:
    # Get the data type of the data at the address
    data_type = data_at_address.getDataType()

    # Print the data type information
    print("Data type at address {}: {}".format(currentAddress, data_type.getName()))
else:
    print("No data found at address {}".format(currentAddress))


ef = currentProgram.getExecutableFormat()
print(ef)
# https://gitlab.com/saruman9/ghidra_scripts/-/blob/master/GetEntryPoints.java
if ef != "Executable and Linking Format (ELF)":
    print("Not an ELF file")
    exit()
currentProgram.getMemory()
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.app.util.bin.format.elf import ElfHeader

# from ghidra.app.util.bin.format.elf import ElfHeaderFactory
# from ghidra.app.util.bin.format.elf import ElfSectionHeader

byteprovider = MemoryByteProvider(
    currentProgram.getMemory(), currentProgram.getImageBase()
)

path = currentProgram.getExecutablePath()
# FileByteProvider(java.io.File(path))
from ghidra.app.util.bin import RandomAccessByteProvider

byteprovider = RandomAccessByteProvider(java.io.File(path))
# public static ElfHeader createElfHeader
print(dir(ElfHeader))
elf = ElfHeader(byteprovider, None)  # RethrowContinuesFactory.INSTANCE, byteProvider)
try:
    elf.parse()
except Exception as e:
    print(e)
phdrs = elf.getProgramHeaders()
for phdr in phdrs:
    print(phdr.getType())
print(dir(elf))
print(elf.e_phoff())
print(elf.e_flags())
print(elf.e_entry())
# print(elf.e_phnum())
print(elf.getSection(".text"))
print(elf.getProgramHeaderCount())
print(elf.getProgramHeaderProgramHeader())
print(elf.getProgramHeaderAt(currentAddress.getOffset()))
"""
