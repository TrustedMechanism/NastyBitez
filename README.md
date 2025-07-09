# NastyBitez Detector for Ghidra

This Ghidra plugin detects "nasty bytes" — byte patterns deliberately crafted to hinder accurate disassembly by triggering confusing control flow or causing Ghidra to interpret jumps to invalid or out-of-bounds addresses. These patterns often exploit instruction overlaps, hidden calls/jumps, or anomalous instruction sequences to obscure program logic and disrupt function boundary analysis.

The plugin scans for known problematic byte signatures, including but not limited to:

    Conditional jumps followed by hidden CALLs or JMPs (\x74\x01\xE8, \x75\x01\xE9)

    Jumps or returns that confuse function boundaries (\x74\x01\xC3, \x75\x01\xC3)

    Breakpoint traps and undefined instructions (\x74\x01\xCC, \x75\x01\x0F\x0B, \x0F\x0B)

    Infinite loops and weird RET variants (\xEB\xFE, \xF3\xC3)

    Overlapping instruction sequences that exploit flag states to hide calls or jump instructions (\x33\xC0\x74\x01\xE8, \x66\xB8\xEB\x05\x31\xC0\x74\xF9)

    Self-jumps and backward jumps used for control flow obfuscation (\xEB\xFF, \x74\xFE, \x75\xFE)

By identifying these patterns, the plugin aids reverse engineers in uncovering obfuscation techniques designed to mislead disassemblers and improve the accuracy of static analysis in Ghidra.

Example Before Script:\
![image1](https://github.com/user-attachments/assets/9f477f94-6a6f-4f8f-a624-36ae5d549b42)

Example After Script:\
![image2](https://github.com/user-attachments/assets/404ddfab-14e0-4fc3-a137-8fb7ff486eb2)
