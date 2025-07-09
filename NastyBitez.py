# -*- coding: utf-8 -*-
#@author TrustedMechanism
#@category NastyBitez


from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.mem import MemoryAccessException

# Function fixes all bytes at the specified address by patching with NOPs.
def fixBytes(address, listing, pattern):
    # Allows for variable amount of patching.
    new_bytes = [0x90] * len(pattern)
    code_units = listing.getCodeUnits(address, True)
    # Clears the codebytes at the address so Ghidra allows for changing of the bytes.
    for i in range(len(new_bytes)):
        cu = listing.getCodeUnitAt(address.add(i))
        if cu is not None:
            listing.clearCodeUnits(cu.getMinAddress(), cu.getMaxAddress(), False)

    try:
        for i, byte in enumerate(new_bytes):
            # Sets the bytes at the offset of the address with the bytes of the patched code. 
            memory.setByte(address.add(i), byte)
    except MemoryAccessException as e:
        print("Memory write failed: " + str(e))

# Finds all bytes in the program
def findBitez(pattern):
    try:
        currentSignature = fpi.findBytes(currentProgram.getMinAddress(), pattern, -1)    
        if(len(currentSignature) > 0):
            # Outputs all detected occurances to Ghidra console. Addresses are clickable to jump to the dissasembly view. 
            print("Found NastyBitez of type " + str([hex(ord(c)) for c in pattern]) + " at the following addresses: \n")
            addr_str = ""
            for i in range(len(currentSignature)):
                if(i == len(currentSignature) - 1):
                    addr_str += str(currentSignature[i])
                else:
                    addr_str += str(currentSignature[i]) + ", "
            print(addr_str + "\n")

            # Adds plate comments to every occurance of the anti-dissasembly bytes. 
            listing = currentProgram.getListing()
            for addr in range(len(currentSignature)):
                codeUnit = listing.getCodeUnitAt(currentSignature[addr])
                codeUnit.setComment(codeUnit.PLATE_COMMENT, "NastyBite of type " + str([hex(ord(c)) for c in pattern])+ " detected at: " + str(currentSignature[addr]))
                # Calls fix bytes to apply the patch to every located instance.
                fixBytes(currentSignature[addr], listing, pattern)
        else:
            print("No bytes matching signature " + str([hex(ord(c)) for c in pattern]) + " were found")
    except:
        print("Pattern was not able to be utilized.")

fpi = FlatProgramAPI(getCurrentProgram())
memory = currentProgram.getMemory()

signatureList = [
    "\x74\x01\xE8",   # JZ +1, CALL (hidden)
    "\x75\x01\xE8",   # JNZ +1, CALL (hidden)
    "\x74\x01\xE9",   # JZ +1, JMP (hidden)
    "\x75\x01\xE9",   # JNZ +1, JMP (hidden)
    "\x74\x01\xC3",   # JZ +1, RET (confuses function boundaries)
    "\x75\x01\xC3",   # JNZ +1, RET
    "\x74\x01\xCC",   # JZ +1, INT3 (breakpoint trap)
    "\x75\x01\xCC",   # JNZ +1, INT3
    "\x74\x01\x0F\x0B", # JZ +1, UD2 (undefined instruction)
    "\xEB\xFE",       # JMP to self (infinite loop)
    "\xF3\xC3",       # REP RET (weird RET variant)
    "\xE8\x06\x00\x00\x00\x68",  # CALL + string ('h' = 0x68)
    "\x33\xC0\x74\x01\xE8",      # XOR EAX, EAX → ZF = 1 → JZ +1 → hides CALL
    "\x66\xB8\xEB\x05",          # MOV AX, 0x5EB → overlaps with JZ -7
    "\x31\xC0\x75\x01\xC3",      # XOR EAX, EAX → JNZ not taken → RET
    "\xEB\xFF",                # jmp $
    "\x74\xFE",                # jz -2
    "\x75\xFE",                # jnz -2
    "\x66\xB8\xEB\x05\x31\xC0\x74\xF9",  # overlapping impossible disasm
    "\x0F\x0B",                # UD2
]


for signature in signatureList:
    findBitez(signature)