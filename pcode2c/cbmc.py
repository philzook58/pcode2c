import subprocess
import tempfile


def single(precond, postcond, equality=False):
    return f"""\
int main(){{
    CPUState state;
    init_state(&state);
    __CPROVER_assume({precond});
    pcode2c(&state, -1);
    __CPROVER_assert({postcond});
}}"""


def comparative(precond, postcond, equality=False):
    return f"""\
int main(){{
    CPUState state_orig, state_mod;
    __CPROVER_assume({precond});
    pcode2c_orig(&state_orig, -1);
    pcode2c_mod(&state_mod, -1);
    __CPROVER_assert({postcond}, "Postcondition");
}}"""


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
