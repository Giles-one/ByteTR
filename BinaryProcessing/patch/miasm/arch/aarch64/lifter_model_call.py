#-*- coding:utf-8 -*-

from miasm.ir.analysis import LifterModelCall
from miasm.arch.aarch64.sem import Lifter_Aarch64l, Lifter_Aarch64b

# newly added
from miasm.ir.ir import AssignBlock
from miasm.expression.expression import ExprAssign, ExprOp, ExprId

class LifterModelCallAarch64lBase(Lifter_Aarch64l, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Aarch64l.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class LifterModelCallAarch64bBase(Lifter_Aarch64b, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Aarch64b.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class LifterModelCallAarch64l(LifterModelCallAarch64lBase):

    def __init__(self, loc_db):
        LifterModelCallAarch64lBase.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0

    # newly added
    def call_effects_systemV(self, ad, instr):
        call_assignblk = AssignBlock([
            ExprAssign(ExprId('dummy1', 64), ExprOp('call_func_arg1', ad, self.arch.regs.X0)),
            ExprAssign(ExprId('dummy2', 64), ExprOp('call_func_arg2', ad, self.arch.regs.X1)),
            ExprAssign(ExprId('dummy3', 64), ExprOp('call_func_arg3', ad, self.arch.regs.X2)),
            ExprAssign(ExprId('dummy4', 64), ExprOp('call_func_arg4', ad, self.arch.regs.X3)),
            ExprAssign(ExprId('dummy5', 64), ExprOp('call_func_arg5', ad, self.arch.regs.X4)),
            ExprAssign(ExprId('dummy6', 64), ExprOp('call_func_arg6', ad, self.arch.regs.X5)),
            ExprAssign(self.ret_reg, ExprOp('call_func_ret', ad)),
            ExprAssign(self.sp, ExprOp('call_func_stack', ad, self.sp))
        ], instr)
        return [call_assignblk], []

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

    def sizeof_char(self):
        return 8

    def sizeof_short(self):
        return 16

    def sizeof_int(self):
        return 32

    def sizeof_long(self):
        return 32

    def sizeof_pointer(self):
        return 32


class LifterModelCallAarch64b(LifterModelCallAarch64bBase, LifterModelCallAarch64l):

    def __init__(self, loc_db):
        LifterModelCallAarch64bBase.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0
