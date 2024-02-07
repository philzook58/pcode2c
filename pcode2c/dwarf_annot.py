import argparse
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr,
    set_global_machine_arch,
    describe_reg_name,
)
import os
import sys


# https://github.com/eliben/pyelftools/blob/8b97f5da6838791fd5c6b47b1623fb414daed2f0/scripts/dwarfdump.py#L136
def get_full_file_path(die, dwarfinfo, cu):
    line_program = dwarfinfo.line_program_for_CU(cu)
    file_entry = die.attributes.get("DW_AT_decl_file")

    if file_entry:
        file_index = file_entry.value
        file_name = line_program["file_entry"][file_index - 1].name.decode("utf-8")
        dir_index = line_program["include_directory"][file_index - 1]
        dir_name = dir_index.decode("utf-8") if dir_index else ""
        full_path = os.path.join(dir_name, file_name)
        return full_path
    else:
        return "Unknown"


def process_elf_file(filename):
    with open(filename, "rb") as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            print("No DWARF info found in the file.")
            return die_info

        set_global_machine_arch(elffile.get_machine_arch())
        dwarfinfo = elffile.get_dwarf_info()

        die_info = {}
        for CU in dwarfinfo.iter_CUs():
            dwarfinfo.line_program_for_CU(CU)
            for DIE in CU.iter_DIEs():
                if DIE.tag in ["DW_TAG_label", "DW_TAG_variable"]:
                    name = DIE.attributes["DW_AT_name"].value.decode("utf-8")
                    line_number = DIE.attributes.get("DW_AT_decl_line").value
                    column_number = DIE.attributes.get("DW_AT_decl_column").value
                    file_name = get_full_file_path(DIE, dwarfinfo, CU)
                    low_pc = DIE.attributes.get("DW_AT_low_pc")
                    low_pc_value = f"0x{low_pc.value:X}" if low_pc else "Unknown"
                    # Collecting DIE information
                    die_info.setdefault(file_name, []).append(
                        {
                            "line": line_number,
                            "name": name,
                            "type": DIE.tag,
                            "column": column_number,
                            "low_pc": low_pc_value,
                            # Other attributes as needed
                        }
                    )

    return die_info


def die_var2C(var):
    return f"""
    decomp(state, {var.addr});
    assert(state->gr[{var.loc}] == {var.name});"""


def die_label2C(label):
    return f"decomp(&state, {label['low_pc']}); "


def patch_data2C(patch_data):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DWARF annotation tool")
    parser.add_argument("input", help="Input file")
    parser.add_argument("-p", "--patch", help="Patch Data")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()
    print(args.input)
    print(args.output)
    die_info = process_elf_file(args.input)
    print(die_info)
    for filename, dies in die_info.items():
        print(filename)
        # Sorting entries in reverse order of line number
        dies.sort(key=lambda x: x["line"], reverse=True)
        with open(filename, "r") as f:
            with sys.stdout if args.output == None else open(args.output, "w") as o:
                lines = f.readlines()
                for entry in dies:
                    line_num = entry["line"]
                    if entry["type"] == "DW_TAG_label":
                        comment = die_label2C(entry)
                    else:
                        comment = ""
                    comment += f"// {entry['type']} {entry['name']}\n"
                    if line_num <= len(lines):
                        lines.insert(line_num - 1, comment)
                o.writelines(lines)
