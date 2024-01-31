import subprocess
import tempfile


def run_cbmc(filename, args):
    subprocess.run(["cbmc", filename, *args])


if __name__ == "__main__":
    args = argparse.ArgumentParser(description="Run CBMC on a C file")
    args.add_argument("filename")
    args.add_argument("--precond", default="true")
    args.add_argument("--postcond", default="true")
    args.parse_args()
    with tempfile.NamedTemporaryFile() as f:
        standalone = pcode2c(filename)
        f.write(standalone.encode("utf-8"))
        f.write(single_template(args.precond, args.postcond))
        f.flush()
        run_cbmc(f.name, args.nargs)
