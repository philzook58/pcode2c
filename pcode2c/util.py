import subprocess
import tempfile


# Also consider looking here https://docs.pwntools.com/en/stable/asm.html
def asm(code):
    with tempfile.NamedTemporaryFile(suffix=".s") as f:
        f.write(code.encode("utf-8"))
        f.flush()
        binfile = f.name + ".out"
        subprocess.run(["gcc", "-nostdlib", "-o", binfile, f.name])
        with open(binfile, "rb") as f:
            return f.read()
