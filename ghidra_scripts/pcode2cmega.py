# @category: PCode2C
# @toolbar boom.png
# @menupath Pcode2C.mega


from javax.swing import (
    JButton,
    JPanel,
    JScrollPane,
    JFrame,
    JTextPane,
)
from javax.swing.text import StyleConstants, SimpleAttributeSet
from java.awt import BorderLayout, Dimension
import subprocess
from java.io import File
from ghidra.features.base.values import GhidraValuesMap
import random

# from pcode2c import PCode2C
# from cbmc import CBMC

import os
import pcode2c_util

script_path = __file__  # str(getScriptSourceFile().getAbsolutePath())
script_dir = os.path.dirname(script_path)  # File(script_path).get_Parent()
harness_template = open(script_dir + "/../templates/harness.c", "r").read()
pcode_header = open(script_dir + "/../templates/_pcode.h", "r").read()


def run_verify(harness_code):
    code = run_pcode2c()
    cbmc_file = "/tmp/cbmc_test.c"
    with open(cbmc_file, "w") as f:

        def write(s):
            print(s)
            f.write(s)

        # f.write("//****** HEADER *********\n")
        # f.write(pcode_header)
        write("//****** Interpreter *********\n")
        write("\n".join(code))
        write("//****** HARNESS *********\n")
        write(harness_code)
        f.flush()
    run_cbmc(cbmc_file)


# Todo. Refactor calling subprocess code to be shared.
# Put all buttons in main panel.
# Save harness code between invocations?
def main():
    frame = JFrame("Harness Code")
    frame.setSize(700, 400)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

    code_panel = JPanel()

    patches_textarea = JTextPane()  # JTextArea(20, 80)
    patches_textarea.setPreferredSize(Dimension(700, 400))
    patches_textarea.setText(harness_template)
    patches_textarea.setEditable(True)
    scrollPane = JScrollPane(patches_textarea)
    code_panel.add(scrollPane, BorderLayout.CENTER)

    frame.add(code_panel)

    button = JButton(
        "Verify",
        actionPerformed=lambda event: run_verify(patches_textarea.getText()),
    )
    doc = patches_textarea.getStyledDocument()

    def callback(event):
        comment = SimpleAttributeSet()
        StyleConstants.setForeground(comment, java.awt.Color(0, 128, 0))
        l = patches_textarea.getText()
        startIndex = 0
        for line in l.split("\n"):
            line_index = line.find("//")
            if line_index != -1:
                doc.setCharacterAttributes(
                    startIndex + line_index, len(line) - line_index, comment, False
                )
            startIndex += len(line) + 1

    # callback("whatev")
    pcode2c_util.C_syntax_highlight(doc)
    # doc.addDocumentListener(callback)
    frame.add(button, BorderLayout.SOUTH)

    frame.pack()
    frame.setVisible(True)


# This is not really acceptable.
# bg copy and paste


def run_pcode2c():
    func = getFunctionContaining(currentAddress)
    funcname = func.getName()

    startAddress = func.getEntryPoint()

    endAddress = func.getBody().getMaxAddress()
    listing = currentProgram.getListing()
    insn = listing.getInstructionContaining(endAddress)
    endAddress = endAddress.add(insn.getLength())
    size = endAddress.subtract(startAddress)

    memory = currentProgram.getMemory()
    block = memory.getBlock(startAddress)
    mb_source_info = block.getSourceInfos()[0]
    if block and block.getStart().getOffset() != 0:
        file_offset = (
            startAddress.getOffset()
            - block.getStart().getOffset()
            + mb_source_info.getFileBytesOffset()
        )
    else:
        file_offset = None

    language = currentProgram.getLanguageCompilerSpecPair()
    filename = currentProgram.getExecutablePath()
    print(hex(file_offset))
    values = ghidra.features.base.values.GhidraValuesMap()
    values.defineFile("Bin File", java.io.File(filename))  # get current file
    values.defineAddress("Start Address", startAddress, currentProgram)
    values.defineInt("File Offset", file_offset)
    values.defineInt("Size", size)
    # values.defineFile(
    #    "Out File", java.io.File(filename + ".pcode2c." + funcname + ".c")
    # )  # get current file
    values.defineLanguage("Language", language)

    # Super hacky way to get it to clear itself 9 times uot of 10
    # Ghidra is caching the askvules based on the title
    _ = askValues("Pcode2C" + " " * random.randint(100, 200), None, values)
    command = [
        "python3",
        "-m",
        "pcode2c",
        str(values.getFile("Bin File")),
        "--headers",
        "-b",
        str(values.getLanguage("Language").getLanguageID()),
        "--start-address",
        "0x" + str(values.getAddress("Start Address")),
        "--file-offset",
        str(hex(values.getInt("File Offset"))),
        "--size",
        str(hex(values.getInt("Size"))),
        # "--end-address",
        # str(values.getAddress("End Address")),
    ]
    del values
    print(command)

    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Poll process for new output until finished
    code = []
    while True:
        # Try to read from stdout
        output = proc.stdout.readline()
        if output:
            print(output.rstrip())
            code.append(output)

        # Try to read from stderr
        err = proc.stderr.readline()
        if err:
            print(err.rstrip())

        # Check if process has terminated
        if proc.poll() is not None:
            break

    # Make sure we read any remaining output after the process has finished
    for output in proc.stdout.readlines():
        print(output.rstrip())
        code.append(output)
    for err in proc.stderr.readlines():
        print(err.rstrip())

    # Close subprocess' file descriptors
    proc.stdout.close()
    proc.stderr.close()
    proc.kill()
    return code


def run_cbmc(cfile):
    values = GhidraValuesMap()
    values.defineInt("Unwind", 1)
    values.defineInt("Object Bits", 8)
    values.defineChoice("Solver", "default", "default", "smt2", "boolector")
    values.defineString(
        "Options",
        "--bounds-check --conversion-check --div-by-zero-check --float-overflow-check --malloc-fail-null \
        --malloc-may-fail --nan-check --pointer-check --pointer-overflow-check --pointer-primitive-check \
        --signed-overflow-check --undefined-shift-check --unsigned-overflow-check --memory-leak-check",
    )
    values = askValues("CBMC", None, values)
    # TODO get arch, get bits, get endianess
    command = [
        "cbmc",
        cfile,
        "-I",
        script_dir + "/../templates/",
        "--unwind",
        str(values.getInt("Unwind")),
        "--object-bits",
        str(values.getInt("Object Bits")),
        "--unwinding-assertions",
    ] + values.getString("Options").split()

    solver = values.getChoice("Solver")
    if solver != "default":
        command.append("--" + solver)

    print("Running command: `" + " ".join(command) + "`")

    # Start the subprocess with stdout and stderr piped
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    """proc = subprocess.Popen(
        [
            "cbmc",
            "-I",
            script_dir + "/../templates/",
            "--unwind",
            "1",
            "/tmp/cbmc_test.c",
            "--flush",
            # "--stop-on-fail",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )"""

    # Poll process for new output until finished
    while True:
        # Try to read from stdout
        output = proc.stdout.readline()
        if output:
            print(output.rstrip())

        # Try to read from stderr
        err = proc.stderr.readline()
        if err:
            print(err.rstrip())

        # Check if process has terminated
        if proc.poll() is not None:
            break

    # Make sure we read any remaining output after the process has finished
    for output in proc.stdout.readlines():
        print(output.rstrip())
    for err in proc.stderr.readlines():
        print(err.rstrip())

    # Close subprocess' file descriptors
    proc.stdout.close()
    proc.stderr.close()
    proc.kill()


if __name__ == "__main__":
    main()
