import subprocess
import tempfile


def single(precond, postcond, equality=False):
    """
    main with a single pcode2c
    """
    return f"""\
int main(){{
    CPUState state;
    init_state(&state);
    __CPROVER_assume({precond});
    pcode2c(&state, -1);
    __CPROVER_assert({postcond});
}}"""


def comparative(precond, postcond, equality=False):
    """
    main with 2 pcode2c calls
    """
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
    cl_args_parse = argparse.ArgumentParser(description="Run CBMC on a C file")
    cl_args_parse.add_argument("filename")
    cl_args_parse.add_argument("--precond", default="true")
    cl_args_parse.add_argument("--postcond", default="true")
    cl_args_parse.parse_args()
    with tempfile.NamedTemporaryFile() as f:
        standalone = pcode2c(filename)
        f.write(standalone.encode("utf-8"))
        f.write(single_template(cl_args_parse.precond, cl_args_parse.postcond))
        f.flush()
        run_cbmc(f.name, cl_args_parse.nargs)
