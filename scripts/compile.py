# @category: PCode2C
# @toolbar icon.gif
# @menupath Pcode2C.compile

# askValues
in_args = askString("Enter register args", "Args")
out_args = askString("Enter out register args", "Args")
code = askString("Enter Patch Code", "Code")
import subprocess

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
    # Could compile and dump objdump
    print(asm)
