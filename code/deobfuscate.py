#using python2
from capstone.x86 import *
from capstone import *
from keystone import *


import sys
sys.setrecursionlimit(20000)


branch = ["JZ","JP", "JO","JS", "JG", "JB", "JA","JL","JE",]
branch_ = ["JNZ" , "JNP", "JNO", "JNS", "JLE", "JNB", "JBE","JGE","JNE", "JAE"]

opcodes = bytearray()
list_offset = [0]
funtions = list()
list_ea = []
jump_branch = []
jmp_context = dict()
call_context = dict()
loop_counter = 0

log_filename = r"mapping_address.txt"
f = open(log_filename,"a")

def write_log(data):
    f.write(data)
    f.write("\n")

def WriteFile(data):
    f = open("Y0da_all_threads.bin", "wb")
    f.write(data)
    f.close()

def SroreCallContext(ea, des_ea, mnemonic):
    new_list = list((des_ea, mnemonic))        
    call_context[ea] = new_list

def SroreJmpContext(ea, des_ea, mnemonic):
    new_list = list((des_ea, mnemonic))        
    jmp_context[ea] = new_list
    
def Relocate(ea, context):


    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    

    index = list_ea.index(ea)
    ea_offet = list_offset[index]
    des_ea = context[ea][0]
    mnemonic = context[ea][1]
    #print (ea, des_ea)
    index1 = list_ea.index(des_ea)
    des_offset = list_offset[index1]

    assembly = mnemonic + ' ' + str(des_offset)
    encoding, _ = ks.asm(assembly, ea_offet)

    patch_data = ''.join(chr(e) for e in encoding)
    old_opcode_len = list_offset[index+1] -ea_offet
    count = len(patch_data)
    for i in range(count):

        opcodes[ea_offet + i] = patch_data[i]
    if count < old_opcode_len:
        for i in range(old_opcode_len - count):
            opcodes[ea_offet+i+count] = 0x90
    
def GetOpcodeFunction(address):
    global jump_branch
    if address not in list_ea:
        list_ea.append(address)
    else:
        return 

    code = get_bytes(address,32)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
        
    md.detail = True
    try:
        insns = md.disasm(code, address)
        insn1 = insns.next()
        insn2 = insns.next()
        insns.close()
        
    except StopIteration:
        pass  

    ### append our opcodes first    
    opcodes.extend(insn1.bytes)
    
    write_log("Old:0x%x, New:0x%x" %(address, list_offset[-1]))

    list_offset.append(list_offset[-1] + insn1.size)

    if insn1.mnemonic == 'jmp' and insn1.operands[0].type != X86_OP_REG:
        next_opcode = int(insn1.op_str,16)
        #list_ea.append(next_opcode)
        SroreJmpContext(address, next_opcode, insn1.mnemonic)
        jump_branch.append(next_opcode)

    if (insn1.mnemonic.upper() in branch or insn1.mnemonic.upper() in branch_ ):  #assert jmp

        jump_addr = int(insn1.op_str,16)
        #print hex(address)
        if jump_addr in list_ea:
            SroreJmpContext(address, jump_addr, insn1.mnemonic)
            
        else:
            jump_branch.append(jump_addr)
            SroreJmpContext(address, jump_addr, insn1.mnemonic)

    #add to list funtions       
    if insn1.mnemonic == 'call' and insn1.operands[0].type == X86_OP_IMM:
        jump_addr = int(insn1.op_str,16)
        funtions.append(jump_addr)
        SroreCallContext(address,jump_addr,insn1.mnemonic  )

 
    if insn2.mnemonic == 'jmp' and insn1.mnemonic != 'ret':
        next_opcode = int(insn2.op_str,16)    
        GetOpcodeFunction(next_opcode)

    #handle Branch 
    for i in jump_branch:
        GetOpcodeFunction(i)
    
    

#Add Thread 2 to list of functions
funtions.append(0x18004E0E7 )

#Add Thread 1
funtions.append(0x18004928C )

#Start with entry point 
GetOpcodeFunction(0x0000000180032701)

#Walking all functions
for i in funtions:
    GetOpcodeFunction(i)

#Relocate jmp branch
for i in jmp_context:
    Relocate(i, jmp_context)

#Reloc relative call 
for i in call_context:
    Relocate(i, call_context)

WriteFile(opcodes)    
f.close()