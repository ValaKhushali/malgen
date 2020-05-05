MalGen
======

.. code-block::

   usage: malgen.py [-h] [-e] [-o] payload output

   Craft obfuscated, fileless PowerShell malware.

   positional arguments:

     payload          Raw-formatted 32-bit binary payload
     output           Output file path

   optional arguments:

     -h, --help       show this help message and exit
     -e, --encode     Base64-encode output
     -o, --obfuscate  Obfuscate output

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

Additional Considerations
-------------------------
The output of this script can be fairly large. It is important to
consider the constraints of your payload transmission method when
choosing to encode or obfuscate the payload.

* If transmitting via a remote shell such as `netcat`, your commands
  may be limited to 4,096 bytes.
* If pasting the command into an instance of `cmd.exe`, the command is
  limited to 8,192 bytes.
* If pasting the command directly into `powershell.exe`, the command
  is limited to 32,767 bytes.

With local or SSH access, there is one workaround to these buffer-size
limitations. Simply type `powershell.exe -` and hit enter, then paste
your payload, sans the preceding `powershell` and its command-line
flags.

Final Note
----------
This software is provided purely for educational, legal purposes. The author
does not condone nor promote the use of this script for any unethical or
illegal purposes. What you do with this is your own business.
