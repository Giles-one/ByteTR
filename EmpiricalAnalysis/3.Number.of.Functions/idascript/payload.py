import json

import idc
import idaapi
import idautils

import ida_pro
import ida_nalt
import ida_lines
import ida_funcs
import ida_segment
import ida_hexrays

from ida_hexrays import decompile, DecompilationFailure

# import pydevd_pycharm
# pydevd_pycharm.settrace('localhost', port=2345, stdoutToServer=True, stderrToServer=True)

# ================================================
class cfunc_graph_t():
    def __init__(self):
        self.items = [] # list of citem_t
        self.objs = []
        self.succs = [] # list of lists of next nodes
        self.preds = [] # list of lists of previous nodes

    def reinit(self):
        self.items = []
        self.succs = []
        self.preds = []

    def add_node(self):
        n = self._size()

        def resize(array, new_size):
            if new_size > len(array):
                while len(array) < new_size:
                    array.append([])
            else:
                array = array[:new_size]
            return array

        self.preds = resize(self.preds, n+1)
        self.succs = resize(self.succs, n+1)
        return n

    def add_edge(self, x, y):
        self.preds[y].append(x)
        self.succs[x].append(y)


    def _set_objs(self, objs):
        self.objs = objs

    def _nsucc(self, n):
        return len(self.succs[n]) if self._size() else 0

    def _npred(self, n):
        return len(self.preds[n]) if self._size() else 0

    def _succ(self, n, i):
        return self.succs[n][i]

    def _pred(self, n, i):
        return self.preds[n][i]

    def _size(self):
        return len(self.preds)

    def _get_expr_name(self, expr):
        name = expr.print1(None)
        name = ida_lines.tag_remove(name)
        name = ida_pro.str2user(name)
        return name

    def _get_node_label(self, n, highlight_node=False):
        item = self.items[n]
        op = item.op
        insn = item.cinsn
        expr = item.cexpr
        type_name = ida_hexrays.get_ctype_name(op)
        parts = []

        if op == ida_hexrays.cot_ptr:
            parts.append("%s.%d" % (type_name, expr.ptrsize))
        elif op == ida_hexrays.cot_memptr:
            parts.append("%s.%d (m=%d)" % (type_name, expr.ptrsize, expr.m))
        elif op == ida_hexrays.cot_memref:
            parts.append("%s (m=%d)" % (type_name, expr.m,))
        elif op in [
                ida_hexrays.cot_obj,
                ida_hexrays.cot_var]:
            name = self._get_expr_name(expr)
            parts.append("%s.%d %s" % (type_name, expr.refwidth, name))
            if op == ida_hexrays.cot_obj:
                parts.append("obj_ea: %x" % item.obj_ea)
        elif op in [
                ida_hexrays.cot_num,
                ida_hexrays.cot_helper,
                ida_hexrays.cot_str]:
            name = self._get_expr_name(expr)
            parts.append("%s %s" % (type_name, name,))
        elif op == ida_hexrays.cit_goto:
            parts.append("%s LABEL_%d" % (type_name, insn.cgoto.label_num))
        elif op == ida_hexrays.cit_asm:
            parts.append("%s <asm statements; unsupported ATM>" % type_name)
            # parts.append(" %a.%d" % ())
        else:
            parts.append("%s" % type_name)

        parts.append("ea: %x" % item.ea)
        # add type
        if item.is_expr() and not expr.type.empty():
            tstr = expr.type._print()
            parts.append(tstr if tstr else "?")

        if self.debug:
            parts.append("-"*20)
            parts.append("obj_id: %x" % item.obj_id)
            if op is ida_hexrays.cot_var:
                parts.append("idx: %d" % expr.v.idx)
                lv = expr.v.getv()                        
                if lv:
                    parts.append("width: %d" % lv.width)
                    parts.append("defblk: %d" % lv.defblk)
                    parts.append("cmt: %s" % lv.cmt)
                    parts.append("arg_var: %r" % lv.is_arg_var)
                    parts.append("thisarg: %r" % lv.is_thisarg())
                    parts.append("result_var: %r" % lv.is_result_var)
                    parts.append("used_byref: %r" % lv.is_used_byref())
                    parts.append("mapdst_var: %r" % lv.is_mapdst_var)
                    parts.append("overlapped_var: %r" % lv.is_overlapped_var)
                    parts.append("floating_var: %r" % lv.is_floating_var)
                    parts.append("typed: %r" % lv.typed)
                    if self.debug > 1:
                        parts.append("divisor: %d" % lv.divisor)
                        parts.append("automapped: %r" % lv.is_automapped())
                        parts.append("fake_var: %r" % lv.is_fake_var)
                        parts.append("spoiled_var: %r" % lv.is_spoiled_var)
                        parts.append("noptr_var: %r" % lv.is_noptr_var())
                        parts.append("forced_var: %r" % lv.is_forced_var())
                        parts.append("dummy_arg: %r" % lv.is_dummy_arg())
                        parts.append("used: %r" % lv.used)
                        parts.append("user_info: %r" % lv.has_user_info)
                        parts.append("user_name: %r" % lv.has_user_name)
                        parts.append("user_type: %r" % lv.has_user_type)
                        parts.append("regname: %r" % lv.has_regname())
                        parts.append("mreg_done: %r" % lv.mreg_done)
                        parts.append("nice_name: %r" % lv.has_nice_name)
                        parts.append("unknown_width: %r" % lv.is_unknown_width)
                        parts.append("in_asm: %r" % lv.in_asm())
                        parts.append("notarg: %r" % lv.is_notarg())
                        parts.append("decl_unused: %r" % lv.is_decl_unused())

        # disable hightlight color for now -> requires labels to be re-generated/graph to be redrawn
        #scolor = self.COLOR_TEXT_HIGHLIGHT if highlight_node else self.COLOR_TEXT_DEFAULT
        scolor = self.COLOR_TEXT_DEFAULT
        parts = [ida_lines.COLSTR("%s" % part, scolor) for part in parts]
        return "\n".join(parts)

    def _get_node_info(self, n):
        item = self.items[n]
        color = 0
        focus_node = False
        highlight_node = False

        # is curent node an item that belongs to current pseudocode line?
        if self.objs is not None and item.obj_id in self.objs:
            highlight_node = True

        if self.focus is not None and item.obj_id == self.focus:
            focus_node = True

        # handle COT_
        if item.is_expr():
            # handle call
            if item.op == ida_hexrays.cot_call:
                color = self.COLOR_NODE_COT_CALL
            else:
                color = self.COLOR_NODE_COT
        # handle CIT_
        elif ida_hexrays.is_loop(item.op):
            color = self.COLOR_NODE_CIT_LOOP
        else:
            color = self.COLOR_NODE_CIT

        return (focus_node, highlight_node, color)


# -----------------------------------------------------------------------
class graph_builder_t(ida_hexrays.ctree_parentee_t):
    def __init__(self, cg):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self.cg = cg
        self.n_items = None
        self.n_processed = 0
        self.cg.reinit()
        self.reverse = {} # citem_t -> node#

    def _add_node(self, i):
        n = self.cg.add_node()
        if n <= len(self.cg.items):
            self.cg.items.append(i)
        self.cg.items[n] = i
        self.reverse[i.obj_id] = n
        return n

    def _process(self, i):
        n = self._add_node(i)
        self.n_processed += 1
        if n < 0:
            return n
        if len(self.parents) > 1:
            lp = self.parents.back().obj_id
            for k_obj_id, v in self.reverse.items():
                if k_obj_id == lp:
                    p = v
                    break
            self.cg.add_edge(p, n)
        return 0

    def visit_insn(self, i):
        return self._process(i)

    def visit_expr(self, e):
        return self._process(e)


def collectFunctionCall(cfunc):
    if cfunc is None:
        return []

    try:
        CFuncGraph = cfunc_graph_t()
        CFuncGraphBuilder = graph_builder_t(CFuncGraph)
        CFuncGraphBuilder.apply_to(cfunc.body, None)
    except:
        return []

    callNodes = list()
    for idx, item in enumerate(CFuncGraph.items):
        if item.op == ida_hexrays.cot_call:
            callNodes.append((idx, item))

    def parseCallArgument(graph, citemIdx):
        ## Stupid Algo
        # visited = set()
        # def dfs(node):
        #     if node in visited:
        #         return
        #     visited.add(node)
        #     citem = graph.items[node]
        #     op = citem.op
        #     expr = citem.cexpr
        #     if op in [
        #         ida_hexrays.cot_obj,
        #         ida_hexrays.cot_var]:
        #         name = graph._get_expr_name(expr)
        #         collect.append(name)
        #
        #     for successor in graph.succs[node]:
        #         dfs(successor)
        # dfs(citemIdx)
        citem = graph.items[citemIdx]
        expr = citem.cexpr
        return graph._get_expr_name(expr)

    def parseCallFunction(graph, citemIdx):
        citem = graph.items[citemIdx]
        if citem.op != ida_hexrays.cot_obj:
            return ""
        expr = citem.cexpr
        name = graph._get_expr_name(expr)
        return name

    callingCollect = list()
    for idx, callNode in callNodes:
        children = CFuncGraph.succs[idx]
        if len(children) == 0:
            continue
        fnNode = children[0]
        fnName = parseCallFunction(CFuncGraph, fnNode)
        if not fnName:
            continue

        argsExpr = list()
        for child in children[1:]:
            argExpr = parseCallArgument(CFuncGraph, child)
            argsExpr.append(argExpr)
        info = {
            'calledName': fnName,
            'argsExpr': argsExpr
        }
        callingCollect.append(info)
    return callingCollect
# functionCallInfo = collectFunctionCall(0x2D60)
# print(functionCallInfo)
# ======================================================

# ======================================================
def collectFuncsInText():
    seg = ida_segment.get_first_seg()
    while seg:
        segName = ida_segment.get_segm_name(seg)
        if '.text' == segName:
            funcsInSeg = list(idautils.Functions(seg.start_ea, seg.end_ea))
            return funcsInSeg
        seg = ida_segment.get_next_seg(seg.start_ea)
    return []

def demangle(name, disable_mask=0):
    demangled_name = idaapi.demangle_name(name, disable_mask, idaapi.DQT_FULL)
    if demangled_name:
        return demangled_name
    return name

def collectVarInfo(varList):
    varInfoCollect = []
    for var in varList:
        varName = var.name
        varType = var.type()
        varInfoCollect.append({
            'varName': varName,
            'varType': str(varType),
            'isPtr': varType.is_ptr(),
            'isStruct': varType.is_struct(),
            'isEnum': varType.is_enum(),
            'isUnion': varType.is_union()
        })
    return varInfoCollect
# ======================================================

filePath = ida_nalt.get_input_file_path()
print('[+] Input File Path %s' % filePath)

funcs = collectFuncsInText()
print("[+] Collect Function %d" % len(funcs))
# if len(funcs) == 0:
#     ida_pro.qexit(0)

dummyFunctions = ("_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy")

collectInfo = list()
for funcEA in funcs:
    func = ida_funcs.get_func(funcEA)
    if not func:
        continue

    if func.flags & ida_funcs.FUNC_THUNK:
        continue

    funcStart = func.start_ea
    funcEnd = func.end_ea
    funcName = idc.get_func_name(funcStart)
    if funcName in dummyFunctions:
        continue
    demangledFuncName = demangle(funcName)

    print("[+] handling %s %x" % (funcName, funcStart))
    try:
        cfunc = decompile(funcStart)
    except DecompilationFailure:
        print("[!] Failed to decompile function 0x%x " % (funcStart))
        continue

    if cfunc is None:
        continue

    paraInfo = collectVarInfo(cfunc.arguments)
    lvarInfo = collectVarInfo(cfunc.lvars)
    if len(paraInfo) + len(lvarInfo) == 0:
        continue

    functionCallInfo = collectFunctionCall(cfunc)
    collectInfo.append({
        'functionName': demangledFuncName,
        'functionStart': funcStart,
        'parameter': paraInfo,
        'lvariable': lvarInfo,
        'call': functionCallInfo
    })

print('[+] Actually Collect Function %d' % len(collectInfo))

SUFFIX = '.ea.exp2.json'
saveTo = filePath + SUFFIX
print('[+] Save To %s' % saveTo)

with open(saveTo, 'w') as fp:
    json.dump(collectInfo, fp, indent=2)

ida_pro.qexit(0)
