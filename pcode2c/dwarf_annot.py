import os
import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr,
    set_global_machine_arch,
    describe_reg_name,
)


def get_full_file_path(die, dwarfinfo, cu) -> str:
    """
    https://github.com/eliben/pyelftools/blob/8b97f5da6838791fd5c6b47b1623fb414daed2f0/scripts/dwarfdump.py#L136
    """
    line_program = dwarfinfo.line_program_for_CU(cu)
    file_entry = die.attributes.get("DW_AT_decl_file")

    if file_entry:
        file_index = file_entry.value
        file_name = line_program["file_entry"][file_index - 1].name.decode("utf-8")
        dir_index = line_program["include_directory"][file_index - 1]
        dir_name = dir_index.decode("utf-8") if dir_index else ""
        full_path = os.path.join(dir_name, file_name)
        return full_path
    return "Unknown"


from elftools.dwarf.locationlists import LocationParser


def linetable(dwarfinfo):
    """
    process linetable
    """
    for CU in dwarfinfo.iter_CUs():
        lineprogram = dwarfinfo.line_program_for_CU(CU)
        for entry in lineprogram.get_entries():
            if entry.state is not None:
                print(entry.state)
        return lineprogram


def locations_info(dwarfinfo):
    """
    get AT_location info from dwarfinfo
    """
    llp = dwarfinfo.location_lists()
    locparser = LocationParser(llp)
    my_vars = {}
    for CU in dwarfinfo.iter_CUs():
        for die in CU.iter_DIEs():
            if die.tag == "DW_TAG_variable":
                loc = die.attributes.get("DW_AT_location")
                if loc:
                    myloc = locparser.parse_from_attribute(
                        loc, CU.header.version, die=die
                    )
                    name = die.attributes["DW_AT_name"].value.decode("utf-8")
                    my_vars[name] = myloc
    return my_vars


def process_elf_file(filename):
    with open(filename, "rb") as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            print("No DWARF info found in the file.")
            return die_info

        set_global_machine_arch(elffile.get_machine_arch())
        dwarfinfo = elffile.get_dwarf_info()
        loclists = locations_info(dwarfinfo)
        # for loc_entity in loclists.values:
        #    describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)

        lineprogram = linetable(dwarfinfo)
        for entry in lineprogram.get_entries():
            if entry.is_stmt:
                # check if C code is all whitespace before this.
                line_addr[entry.line] = entry.address

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


def die_var2C(var) -> str:
    # {'line': 10, 'name': 'result', 'type': 'DW_TAG_variable', 'column': 9, 'low_pc': 'Unknown'}
    return f"""DW_TAG_VARIABLE("{var['name']}", {var['low_pc']});\n"""


def die_label2C(label) -> str:
    return f"""DW_TAG_LABEL("{label['name']}", {label['low_pc']});\n"""


def patch_data2C(patch_data):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DWARF annotation tool")
    parser.add_argument("input", help="Input file")
    # parser.add_argument("-p", "--patch", help="Patch Data")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()
    print(args.input)
    # print(args.output)
    main_die_info = process_elf_file(args.input)
    print(main_die_info)
    for main_filename, dies in main_die_info.items():
        print(main_filename)
        # Sorting entries in reverse order of line number
        dies.sort(key=lambda x: x["line"], reverse=True)
        with open(main_filename, "r") as main_f:
            with sys.stdout if args.output is None else open(args.output, "w") as o:
                lines = main_f.readlines()
                for die_entry in dies:
                    if die_entry["type"] == "DW_TAG_variable":
                        comment = die_var2C(die_entry)
                    elif die_entry["type"] == "DW_TAG_label":
                        comment = die_label2C(die_entry)
                    else:
                        comment = f"// {die_entry['type']} {die_entry['name']}\n"
                    line_num = die_entry["line"]
                    if line_num <= len(lines):
                        lines.insert(line_num - 1, comment)
                o.writelines(lines)
