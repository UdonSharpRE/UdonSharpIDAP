import idc
import idaapi
from idc import *
from idaapi import *
import idautils


class usharp_processor_t(processor_t):

    id = 0x8093
    flag = PR_USE32

    cnbits = 8
    dnbits = 8

    psnames = ['udon']
    plnames = ['UdonSharp Byte Code']

    segreg_size = 0
    tbyte_size = 0

    assembler = {
        'flag' : 0,
        'name' : "UdonSharp Byte Code Disassembler",
        'origin': "org",
        'end': "end",
        'cmnt': ";",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': "db",
        'a_byte': "db",
        'a_word': "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        'a_float': "dd",
        'a_dups': "#d dup(#v)",
        'a_bss': "%s dup ?",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': "public",
        'a_weak': "weak",
        'a_extrn': "extrn",
        'a_comdef': "",
        'a_align': "align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
    }

    reg_names = ["CS", "DS"]

    FL_D = 0x0004
    IMMDATA_32 = 2

    instruc_start = 0

    udon_heap_addr = 0

    def reverse_number(self, num):
        return ((num & 0xFF) << 24) | (((num >> 8) & 0xFF) << 16) | (((num >> 16) & 0xFF) << 8) | ((num >> 24) & 0xFF)

    def decode_PUSH(self, insn, opbyte):

        operate_addr = get_wide_dword(insn.ea + 4)

        insn.Op1.type = o_mem
        insn.Op1.dtype = dt_dword
        insn.Op1.value = self.udon_heap_addr + self.reverse_number(operate_addr)
        
        insn.size = 8

    def decode_JNE(self, insn, opbyte):
        operate_addr = get_wide_dword(insn.ea + 4)

        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_dword
        insn.Op1.value = self.reverse_number(operate_addr)

        insn.size = 8

    def decode_JMP(self, insn, opbyte):
        operate_addr = get_wide_dword(insn.ea + 4)

        insn.Op1.type = o_imm
        insn.Op1.dtype = dt_dword
        insn.Op1.value = self.reverse_number(operate_addr)

        insn.size = 8

    def decode_EXTERN(self, insn, opbyte):
        operate_addr = get_wide_dword(insn.ea + 4)

        insn.Op1.type = o_mem
        insn.Op1.dtype = dt_dword
        insn.Op1.value = self.udon_heap_addr + self.reverse_number(operate_addr)

        insn.size = 8

    def decode_COPY(self, insn, opbyte):
        insn.Op1.type = o_void
        insn.size = 4

    def decode_JMP_INDIRECT(self, insn, opbyte):
        operate_addr = get_wide_dword(insn.ea + 4)

        insn.Op1.type = o_mem
        insn.Op1.dtype = dt_dword
        insn.Op1.value = self.udon_heap_addr + self.reverse_number(operate_addr)

        insn.size = 8

    def create_ram_segemnt_for_data(self):
        print("creating udonheap")
        segment = get_segm_by_name('UDON_HEAP')
        if segment:
            self.udon_heap_addr = segment.start_ea
        else:
            heap_size = 0x5000
            heap_start = free_chunk(1, heap_size, -0xF)
            heap_end = heap_start + heap_size
            segment = add_segm(heap_start >> 4, heap_start, heap_end, 'UDON_HEAP', 'DATA', ADDSEG_NOSREG)
            self.udon_heap_addr = heap_start

    def notify_newfile(self, fname):
        print('NewFile: %s' % fname)
        self.create_ram_segemnt_for_data()

    def notify_oldfile(self, fname):
        print('NewFile: %s' % fname)
        self.create_ram_segemnt_for_data()

    def ev_may_be_func(self, insn, state):
        if insn.ea == 0:
            return 100
        if insn.itype == self.itype_PUSH:
            """
            0x0000000000000454  PUSH 0x0000000000000002(__intnl_returnJump_SystemUInt32_0[System.UInt32])
            0x000000000000045C  COPY
            0x0000000000000460  JMP __intnl_returnJump_SystemUInt32_0

            .func_ResetTakers_0x468
            0x0000000000000468  PUSH 0x0000000000000095(__const_SystemUInt32_0[System.UInt32])
            """ 
            opcode = get_wide_dword(insn.ea - 0x8)
            imm = get_wide_dword(insn.ea - 0x4)
            if opcode == 0x08000000 and imm == 0x02:
                return 100
        return 10
    
    # cmt = comment 
    def ev_get_autocmt(self, insn):
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt'](insn)

    def ev_ana_insn(self, insn):
        opcode = get_wide_dword(insn.ea)
        
        if not opcode in self.itable:
            return False
        ins = self.itable[opcode]
        insn.itype = getattr(self, 'itype_' + ins.name)
    
        # call decoder and pass parameters
        ins.d(insn, opcode)

        return True

    def ev_out_mnem(self, ctx):
        insn = ctx.insn
        opcode = get_wide_dword(insn.ea)

        postfix = ""
        ctx.out_tagon(COLOR_MACRO)
        ctx.out_line(self.itable[opcode].name + "   ")
        ctx.out_tagoff(COLOR_MACRO)

        if insn.Op1.type == o_mem:
            postfix += ""
        
        return True

    def ev_out_operand(self, ctx, op):
        insn = ctx.insn
        if op.type in [o_imm, o_mem]:
            
            indirect = insn.itype == self.itype_JUMP_INDIRECT
            if indirect:
                ctx.out_symbol('[')

            ctx.out_value(op, OOFW_32)
            if indirect:
                ctx.out_symbol(']')
            
            return True

        return False


    def ev_out_insn(self, ctx):
        insn = ctx.insn
        feature = insn.get_canon_feature()
        opcode = get_wide_dword(insn.ea)
        
        ctx.out_mnemonic() # this also calls ev_out_mnem

        if feature & CF_USE1:
            ctx.out_one_operand(0)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True


    def ev_emu_insn(self, insn):
        feature = insn.get_canon_feature()
        opcode = get_wide_dword(insn.ea)

        op = insn.Op1;

        if feature & CF_USE1:
            if op.type == o_imm: 
                insn.add_dref(op.value, 0, dr_O)
            elif op.type == o_mem:
                insn.create_op_data(op.addr, op)
                insn.add_dref(op.value, 0, dr_O)

        if(insn.itype in [self.itype_JMP, self.itype_JNE]):
            add_cref(insn.ea, op.value, fl_F)

        return True



    def decode_(self, insn, opbyte):
        pass

    def init_instructions(self):
        class idef:
            """
            Internal class that describes an instruction by:
            - instruction name
            - instruction decoding routine
            - canonical flags used by IDA
            """
            def __init__(self, name, cf, d, cmt = None):
                self.name = name
                self.cf  = cf
                self.d   = d
                self.cmt = cmt

        #
        # Instructions table (w/ pointer to decoder)
        #
        self.itable = {
            0x00: idef(name='NOP', d=self.decode_, cf = 0, cmt = lambda insn: "Do nothing"),

            0x01000000: idef(name='PUSH', d=self.decode_PUSH,  cf = CF_USE1, cmt = lambda insn: "Push variable to stack"),
            0x02000000: idef(name='POP', d=self.decode_, cf = CF_USE1, cmt = lambda insn: "Pop variable from stack"),

            0x04000000: idef(name='JNE', d=self.decode_JNE, cf = CF_USE1 | CF_JUMP, cmt = lambda insn: "Jump if false"),
            0x05000000: idef(name='JMP', d=self.decode_JMP, cf = CF_USE1 | CF_JUMP | CF_STOP, cmt = lambda insn: "Jump to dest address"),
            
            0x06000000: idef(name='EXTERN', d=self.decode_EXTERN, cf = CF_USE1 | CF_CALL,  cmt = lambda insn: "Call external function"),
            0x07000000: idef(name='ANNOTATION', d=self.decode_, cf = CF_USE1 | CF_CALL,  cmt = lambda insn: "Call external function"),
            
            0x08000000: idef(name='JUMP_INDIRECT', d=self.decode_JMP_INDIRECT, cf = CF_USE1 | CF_JUMP,  cmt = lambda insn: "Jump to dest address"),
            0x09000000: idef(name='COPY', d=self.decode_COPY, cf = 0,  cmt = lambda insn: "Copy var1 to var2"),
        }

        Instructions = []
        i = 0
        for x in self.itable.values():
            d = dict(name=x.name, feature=x.cf)
            if x.cmt != None:
                d['cmt'] = x.cmt
            Instructions.append(d)
            setattr(self, 'itype_' + x.name, i)
            i += 1
        self.instruc_end = len(Instructions)
        self.instruc = Instructions

        self.icode_return = 4 # end of analyze sign

    def init_registers(self):
        
        self.reg_first_sreg = 0
        self.reg_last_sreg = 1

        self.reg_code_sreg = 1
        self.reg_data_sreg = 2

    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()


def PROCESSOR_ENTRY():
    return usharp_processor_t()