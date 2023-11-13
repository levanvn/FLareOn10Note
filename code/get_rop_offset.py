from capstone import *
code = get_bytes(0x108E6,0x1598) 
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
offsets = list()
for i in md.disasm(code, 0):
    if i.mnemonic == "add":
        offsets.append(i.operands[1].imm)
print(offsets)