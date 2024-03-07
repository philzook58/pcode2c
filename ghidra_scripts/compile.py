# @category: PCode2C
# @toolbar C_Logo.png
# @menupath Pcode2C.compile

# values = ghidra.features.base.values.GhidraValuesMap()

# askValues
# in_args = askString("Enter register args", "Args")
# out_args = askString("Enter out register args", "Args")

from javax.swing import (
    BorderFactory,
    Box,
    BoxLayout,
    JButton,
    JLabel,
    JPanel,
    JScrollPane,
    JTextArea,
    JTextField,
    JFrame,
    JTextPane,
)
from java.awt import BorderLayout, Component, Dimension
from java.awt.event import ActionListener
import subprocess

template = """\
#include <stdint.h>
#define WRITEREG(name) asm( "" ::"r"(name));
uint64_t CALLBACK({args}); 
uint64_t __attribute__((naked)) PATCHCODE({args}){{
  // **** READ REGISTERS ****
  // Calling convention registers already available.
  // ex: register uint64_t rax asm ("rax");
  // **** END READ REGISTERS ****

  // **** PATCH CODE HERE ****
  
  // **** END PATCH CODE ****

  // **** WRITE REGISTERS ****
  // ex: WRITEREG(rax);
  // By default only calling convention registers are preserved.
  return CALLBACK({params});
  // **** END WRITE REGISTERS ****
}}

// Put Help here.
"""

# could generate this from ghidra?
# can I use GHC abi?
# should I unmacroize and just give comment examples?

# lookup patcherex compiler data. Or maybe just reuse it.
compiler_data = {
    "x86/little/64/default": {
        "cc": "x86_64-linux-gnu-gcc",
        "args": "uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9",
        "options": "-Os -masm=intel -fverbose-asm",
        "params": "rdi, rsi, rdx, rcx, r8, r9",
    },
    "ARM/little/32/v8": {
        "cc": "arm-linux-gnueabi-gcc",
        "args": "uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3",
        "options": "-Os -fverbose-asm -mlittle-endian -march=armv8-a",  # is this even right?
        "params": "r0, r1, r2, r3",
    },
}
"""
    "powerpc": {
        "cc": "powerpc-linux-gnu-gcc",
        "args": "uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r6, uint64_t r7, uint64_t r8",
        "params": "r3, r4, r5, r6, r7, r8",
    },
    "arm64": {
        "cc": "aarch64-linux-gnu-gcc",
        "args": "uint64_t r0, uint64_t r1, uint64_t r2, uint64_t r3",
    },
"""


def run_compiler(code):
    cdata = compiler_data[currentProgram.getLanguage().toString()]
    values = ghidra.features.base.values.GhidraValuesMap()
    values.defineString("Compiler", cdata["cc"])
    values.defineString("Options", cdata["options"])
    values = askValues("Patch", None, values)

    with open("/tmp/patch_code.c", "w") as f:
        f.write(code)
        f.flush()
    try:
        subprocess.check_output(
            [
                "{compiler} -S {options} -c /tmp/patch_code.c -o /tmp/patch_code.s".format(
                    compiler=values.getString("Compiler"),
                    options=values.getString("Options"),
                )
                # "gcc",
                # "-Os",
                # "-S",
                # "-fverbose-asm",
                # "-c",
                # "-o",
                # "/tmp/patch_code.s",
                # "/tmp/patch_code.c",
            ],
            stderr=subprocess.STDOUT,
            shell=True,
        )
    except subprocess.CalledProcessError as e:
        print(e.output)
        raise e

    with open("/tmp/patch_code.s", "r") as f:
        asm = f.read()

        asm = asm.split(".cfi_endproc")[
            0
        ]  # Is this a good idea? There could be important stuff here.
        asm = asm.split(".cfi_startproc")[-1]
        # Could compile and dump objdump
        print("## PATCH CODE START ##")
        print(asm)
        print("## PATCH CODE END ##")


def main():
    cdata = compiler_data[currentProgram.getLanguage().toString()]

    frame = JFrame("Compile C Code")
    frame.setSize(700, 400)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

    code_panel = JPanel()

    patches_textarea = JTextPane()  # JTextArea(20, 80)
    patches_textarea.setPreferredSize(Dimension(700, 400))
    patches_textarea.setText(
        template.format(args=cdata["args"], params=cdata["params"])
    )
    patches_textarea.setEditable(True)
    scrollPane = JScrollPane(patches_textarea)
    code_panel.add(scrollPane, BorderLayout.CENTER)

    frame.add(code_panel)

    button = JButton(
        "Compile",
        actionPerformed=lambda event: run_compiler(patches_textarea.getText()),
    )
    frame.add(button, BorderLayout.SOUTH)

    frame.pack()
    frame.setVisible(True)


main()
