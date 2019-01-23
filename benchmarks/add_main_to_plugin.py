import re
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("file")
args = parser.parse_args()
with open(args.file, 'r') as f:
    c_code = f.read()
    function_name = re.findall(r"protoop_arg_t\s+([^\s]+)\(\s*picoquic_cnx_t\s*\*\s*[^\s]*\)", c_code)[-1]
    #                                            f_name    function parameter       param name
    print("""{}
int main() {{
    picoquic_cnx_t *cnx;
    return {}(cnx);
}}
""".format(c_code, function_name))
