import idaapi
import idautils

from os import unlink
from subprocess import Popen
from tempfile import NamedTemporaryFile

command = ["/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle", "-no-sugar"]

# read the functions to the temporary file
f_mangled = NamedTemporaryFile(delete=True)
for f in Functions():
  func_addr = GetFunctionAttr(f, FUNCATTR_START)
  func_name = GetFunctionName(f)
  f_mangled.write("0x%x, %s\n" % (func_addr, func_name))

# demangle the temporary file to another one
f_mangled.flush()
f_mangled.seek(0)
f_demangled = NamedTemporaryFile(delete=True)
process = Popen(command, stdin=f_mangled, stdout=f_demangled)
process.communicate()
f_mangled.close()

# demangle entries in IDA and append the comment with the previous name
f_demangled.flush()
f_demangled.seek(0)
for entry in f_demangled:
    func_addr, signature = entry.rstrip().split(", ", 1)
    func_addr = int(func_addr, 16)
    previous_name = GetFunctionName(func_addr)

    if signature != previous_name:
        MakeNameEx(func_addr, signature, SN_NOCHECK | SN_NOWARN)
        SetFunctionCmt(func_addr, "%s" % previous_name, repeatable=1)
        Message("[0x%x] %s -> %s\n" % (func_addr, previous_name, signature))

Message("Swift Demangle processing finished!\n")
f_demangled.close()
