# @category: PCode2C
# @toolbar icon.gif
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

template = """\
#include <stdint.h>
#define READREG(name) asm(res, uint64_t)
#define WRITEREG(name)  
uint64_t CALLBACK(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9); 
uint64_t PATCHCODE(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9){
  // extra registers ex: READREG(rax)
  // PATCHCODE HERE
  
  // END PATCHCODE
  // extra registers write
  return CALLBACK(rdi, rsi, rdx, rcx, r8, r9);
}
"""


def run_compiler(code):
    with open("/tmp/patch_code.c", "w") as f:
        f.write(code)
        f.flush()
    try:
        subprocess.check_output(
            [
                "gcc -S -Os -fverbose-asm -c /tmp/patch_code.c -o /tmp/patch_code.s"
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
    frame = JFrame("Compile C Code")
    frame.setSize(700, 400)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

    code_panel = JPanel()

    patches_textarea = JTextPane()  # JTextArea(20, 80)
    patches_textarea.setPreferredSize(Dimension(700, 400))
    patches_textarea.setText(template)
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


import subprocess


def old_call_compiler(code):
    with open("/tmp/patch_code.c", "w") as f:
        f.write(
            """
            void CALLBACK({});
            void PATCHCODE({}) {{
                {}
            CALLBACK({});
                }}
            """.format(
                out_args, in_args, code, out_args
            )
        )
