from collections import namedtuple
from future.utils import viewitems, viewvalues

from sympy import sympify
from miasm.core.graph import DiGraph
from miasm.expression.expression import ExprId, ExprOp, ExprMem, ExprLoc
from miasm.expression.expression import ExprCond, ExprInt, ExprSlice, ExprCompose

from miasm.analysis.data_flow import AssignblkNode

class DiGraphSV(DiGraph):
    '''
    To store singal variable data graph.
    '''
    def  __init__(self, heads, graph, headsBlocks=False, *args, **kwargs):
        # For dot display
        self._filter_node = None
        self._dot_offset = None

        self._blocks = graph.blocks
        self.headsBlock = set()

        if not headsBlocks:
            self._compute_heads_blocks(heads)
        else:
            self.headsBlock = heads

        self._assign_by_call = {}

        super(DiGraphSV, self).__init__(*args, **kwargs)
        self._compute(graph)

    def _compute(self, defuse):
        # add node
        while self.headsBlock:
            node = self.headsBlock.pop()
            if not node in defuse.nodes():
                continue
            if node in self.nodes():
                continue
            self.add_node(node)

            for next_node in defuse.successors(node):
                if self.is_function_call(next_node):
                    self.add_node(next_node)
                else:
                    self.headsBlock.add(next_node)

        # add edge
        for nodeA in self.nodes():
            for nodeB in self.nodes():
                if nodeB not in defuse.successors(nodeA):
                    continue
                self.add_uniq_edge(nodeA, nodeB)

        self.delete_eflags_node_without_child()
        self.delete_orphan_call_node()

    def _compute_heads_blocks(self, heads):
        for head in heads:
            refBlock = self._blocks.get(head[0]).assignblks[head[1]]
            for lval, expr in viewitems(refBlock):
                if 'dummy' in lval.__str__():
                    continue
                self.headsBlock.add(AssignblkNode(head[0], head[1], lval))

    def called_sub_functions(self):
        sub = set()
        for node in self.nodes().copy():
            if not self.is_function_call(node):
                continue
            assignblks = self._blocks.get(node.label)[node.index]
            defassign = assignblks[node.var]
            if defassign.op == 'call_func_ret':
                continue
            if not defassign.op.startswith('call_func_arg'):
                continue

            call_loc = defassign.args[0]
            # call rdx
            if not isinstance(call_loc, ExprLoc):
                continue
            relatedReg = defassign.args[1]
            loc_db = self._blocks.get(node.label).loc_db
            func_addr = loc_db.get_location_offset(call_loc.loc_key)
            sub.add((node, relatedReg, func_addr, defassign))
        return sub

    # filter nodes. delete eflags that has no child
    def delete_eflags_node_without_child(self):
        eflags = ('af', 'zf', 'pf', 'nf', 'of', 'cf')
        for node in self.nodes().copy():
            if not hasattr(node.var, 'name'):
                continue
            if not node.var.name in eflags:
                continue
            if self.successors(node):
                continue
            self.del_node(node)

    def delete_orphan_call_node(self):
        for node in self.nodes().copy():
            if not self.is_function_call(node):
                continue
            if self.successors(node):
                continue
            if self.predecessors(node):
                continue
            self.del_node(node)

    def is_function_call(self, node):
        assignblk = self._blocks.get(node.label)[node.index]
        is_function_call = False
        for lvar, rexpr in dict(assignblk).items():
            if rexpr.is_function_call():
                is_function_call = True
        return is_function_call

    def edge_attr(self, src, dst):
        return {}

    def parseNodeAttr(self, node):
        lbl, index, reg = node
        attr = 'unknown'
        if index == -1:
            argMap = {reg: idx for idx, reg in enumerate(('NONE', 'RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'))}
            attr = 'func_arg_%d' % (argMap[reg.name])
        else:
            src = self._blocks[lbl][index][reg]
            if isinstance(src, ExprCond):
                attr = 'condition'
            elif isinstance(src, ExprInt):
                attr = 'immediate'
            elif isinstance(src, ExprSlice):
                attr = 'slice'
            elif isinstance(src, ExprCompose):
                attr = 'slice'
            elif isinstance(src, ExprId):
                attr = 'identifier'
            elif isinstance(src, ExprMem):
                attr = 'memory'
            elif hasattr(src, 'op'):
                attr = src.op

        return attr

    def parseEdgeAttr(self, src, dst):
        if isinstance(dst, ExprMem):
            return 'store'
        if isinstance(src, ExprMem):
            return 'load'
        return 'data'

    def serializeForStorage(self):
        nodeMap = []
        for node in self.nodes():
            node_id   = self.nodeid(node)
            node_text = self.node2text(node)
            node_attr = self.parseNodeAttr(node)
            nodeMap.append({
                'id': node_id,
                'text': node_text,
                'attr': node_attr
            })

        edges = []
        for src, dst in self.edges():
            edge_attr = self.parseEdgeAttr(src, dst)
            edges.append({
                'link': (self.nodeid(src), self.nodeid(dst)),
                'attr': edge_attr
            })

        return {'node': nodeMap, 'edge': edges}

    def getExprIdGraph(self, nodeMap, edgeMap, nodeId, node, parentNode=None, reverse=False):
        exprIdNode = {
            'id': nodeId,
            'text': 'ExprId'
        }
        nodeId += 1
        nodeMap.append(exprIdNode)

        exprIdNameNode = {
            'id': nodeId,
            'text': 'name@%s' % (node.name)
        }
        nodeId += 1
        nodeMap.append(exprIdNameNode)
        edgeMap.append({
            'link': (exprIdNameNode['id'], exprIdNode['id']),
            'attr': 'Property'
        })

        exprIdSizeNode = {
            'id': nodeId,
            'text': 'size@%d' % (node.size)
        }
        nodeId += 1
        nodeMap.append(exprIdSizeNode)
        edgeMap.append({
            'link': (exprIdSizeNode['id'], exprIdNode['id']),
            'attr': 'Property'
        })

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprIdNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprIdNode['id']),
                    'attr': 'parent'
                })

        return nodeId

    def getExprIntGraph(self, nodeMap, edgeMap, nodeId, node, parentNode=None, reverse=False):
        exprIntNode = {
            'id': nodeId,
            'text': 'ExprInt'
        }
        nodeId += 1
        nodeMap.append(exprIntNode)

        exprIntSizeNode = {
            'id': nodeId,
            'text': 'size@%d' % (node.size)
        }
        nodeId += 1
        nodeMap.append(exprIntSizeNode)
        edgeMap.append({
            'link': (exprIntSizeNode['id'], exprIntNode['id']),
            'attr': 'Property'
        })

        exprValueNode = {
            'id': nodeId,
            'text': 'value@%s' % ('<IMM>')
            # 'text': 'value@%d' % (node.arg)
        }
        nodeId += 1
        nodeMap.append(exprValueNode)
        edgeMap.append({
            'link': (exprValueNode['id'], exprIntNode['id']),
            'attr': 'Property'
        })

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprIntNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprIntNode['id']),
                    'attr': 'parent'
                })

        return  nodeId

    def getExprOpGraph(self, nodeMap, edgeMap, nodeId, node, parentNode=None, reverse=False):
        exprOpNode = {
            'id': nodeId,
            'text': 'ExprOp'
        }
        nodeId += 1
        nodeMap.append(exprOpNode)
        opname = node.op
        if opname.startswith('call_func_arg'):
            nodeid = self.nodeid(node)
            exprOpOpNode = {
                'id': nodeId,
                'text': 'op@%s@%d' % (node.op, nodeid),
            }
        else:
            exprOpOpNode = {
                'id': nodeId,
                'text': 'op@%s' % (node.op),
            }
        nodeId += 1
        nodeMap.append(exprOpOpNode)
        edgeMap.append({
            'link': (exprOpOpNode['id'], exprOpNode['id']),
            'attr': 'Property'
        })

        exprOpSizeNode = {
            'id': nodeId,
            'text': 'size@%d' % (node.size)
        }
        nodeId += 1
        nodeMap.append(exprOpSizeNode)
        edgeMap.append({
            'link': (exprOpSizeNode['id'], exprOpNode['id']),
            'attr': 'Property'
        })

        exprOpArgNode = {
            'id': nodeId,
            'text': 'arg@'
        }
        nodeId += 1
        nodeMap.append(exprOpArgNode)
        edgeMap.append({
            'link': (exprOpArgNode['id'], exprOpNode['id']),
            'attr': 'Property'
        })
        for iterId, argn in enumerate(node.args):
            if isinstance(argn, ExprId):
                nodeId = self.getExprIdGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprInt):
                nodeId = self.getExprIntGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprOp):
                nodeId = self.getExprOpGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprLoc):
                nodeId = self.getExprLocGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprMem):
                nodeId = self.getExprMemGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprOp):
                nodeId = self.getExprOpGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprSlice):
                nodeId = self.getExprSliceGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprCond):
                nodeId = self.getExprCondGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            elif isinstance(argn, ExprCompose):
                nodeId = self.getExprComposeGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprOpArgNode)
            # else:
            #     raise Exception('WTF')

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprOpNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprOpNode['id']),
                    'attr': 'parent'
                })

        return nodeId

    def getExprSliceGraph(self, nodeMap, edgeMap, nodeId, node: ExprSlice, parentNode=None, reverse=False):
        exprSliceNode = {
            'id' : nodeId,
            'text': 'ExprSlice'
        }
        nodeId += 1
        nodeMap.append(exprSliceNode)

        exprSliceStartNode = {
            'id': nodeId,
            'text': 'start@%d' % (node.start)
        }
        nodeId += 1
        nodeMap.append(exprSliceStartNode)
        edgeMap.append({
            'link': (exprSliceStartNode['id'], exprSliceNode['id']),
            'attr': 'Property'
        })

        exprSliceStopNode = {
            'id': nodeId,
            'text': 'stop@%d' % (node.stop)
        }
        nodeId += 1
        nodeMap.append(exprSliceStopNode)
        edgeMap.append({
            'link': (exprSliceStopNode['id'], exprSliceNode['id']),
            'attr': 'Property'
        })

        exprSliceArgNode = {
            'id': nodeId,
            'text': 'arg@'
        }
        nodeId += 1
        nodeMap.append(exprSliceArgNode)
        edgeMap.append({
            'link': (exprSliceArgNode['id'], exprSliceNode['id']),
            'attr': 'Property'
        })
        argv = node.arg
        if isinstance(argv, ExprId):
            nodeId = self.getExprIdGraph(nodeMap, edgeMap, nodeId, argv, exprSliceArgNode)

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprSliceNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprSliceNode['id']),
                    'attr': 'parent'
                })

        return nodeId

    def getExprMemGraph(self, nodeMap, edgeMap, nodeId, node, parentNode=None, reverse=False):
        exprMemNode = {
            'id': nodeId,
            'text': 'ExprMem',
        }
        nodeId += 1
        nodeMap.append(exprMemNode)

        exprMemSizeNode = {
            'id': nodeId,
            'text': 'size@%d' % (node.size)
        }
        nodeId += 1
        nodeMap.append(exprMemSizeNode)
        edgeMap.append({
            'link': (exprMemSizeNode['id'], exprMemNode['id']),
            'attr': 'Property'
        })

        exprMemPtrNode = {
            'id': nodeId,
            'text': 'ptr@'
        }
        nodeId += 1
        nodeMap.append(exprMemPtrNode)
        edgeMap.append({
            'link': (exprMemPtrNode['id'], exprMemNode['id']),
            'attr': 'Property'
        })

        ptr = node.ptr
        if isinstance(ptr, ExprId):
            nodeId = self.getExprIdGraph(nodeMap, edgeMap, nodeId, ptr, parentNode=exprMemPtrNode)
        elif isinstance(ptr, ExprOp):
            nodeId = self.getExprOpGraph(nodeMap, edgeMap, nodeId, ptr, parentNode=exprMemPtrNode)
        elif isinstance(ptr, ExprInt):
            nodeId = self.getExprIntGraph(nodeMap, edgeMap, nodeId, ptr, parentNode=exprMemPtrNode)
        elif isinstance(ptr, ExprSlice):
            nodeId = self.getExprSliceGraph(nodeMap, edgeMap, nodeId, ptr, parentNode=exprMemPtrNode)
        # else:
        #     raise Exception('Not take into considering')

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprMemNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprMemNode['id']),
                    'attr': 'parent'
                })

        return nodeId

    def getExprLocGraph(self, nodeMap, edgeMap, nodeId, node: ExprLoc, parentNode=None, reverse=False):
        exprLocNode = {
            'id': nodeId,
            'text': 'ExprLoc'
        }
        nodeId += 1
        nodeMap.append(exprLocNode)

        exprLocAddrNode = {
            'id': nodeId,
            # 'text': str(node.loc_key)
            'text': '<LOCA>'
        }
        nodeId += 1
        nodeMap.append(exprLocAddrNode)
        edgeMap.append({
            'link': (exprLocAddrNode['id'], exprLocNode['id']),
            'attr': 'property'
        })

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprLocNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprLocNode['id']),
                    'attr': 'parent'
                })


        return nodeId

    def getExprCondGraph(self, nodeMap, edgeMap, nodeId, node: ExprCond, parentNode=None, reverse=False):
        exprCondNode = {
            'id': nodeId,
            'text': 'ExprCond'
        }
        nodeId += 1
        nodeMap.append(exprCondNode)

        exprCondCondNode = {
            'id': nodeId,
            'text': 'cond@'
        }
        nodeId += 1
        nodeMap.append(exprCondCondNode)
        edgeMap.append({
            'link': (exprCondCondNode['id'], exprCondNode['id']),
            'attr': 'Property'
        })
        cond = node.cond
        if isinstance(cond, ExprOp):
            nodeId = self.getExprOpGraph(nodeMap, edgeMap, nodeId, cond, exprCondCondNode)
        elif isinstance(cond, ExprId):
            nodeId = self.getExprIdGraph(nodeMap, edgeMap, nodeId, cond, exprCondCondNode)
        elif isinstance(cond, ExprCond):
            nodeId = self.getExprCondGraph(nodeMap, edgeMap, nodeId, cond, exprCondCondNode)
        elif isinstance(cond, ExprSlice):
            nodeId = self.getExprSliceGraph(nodeMap, edgeMap, nodeId, cond, exprCondCondNode)
        elif isinstance(cond, ExprMem):
            nodeId = self.getExprMemGraph(nodeMap, edgeMap, nodeId, cond, exprCondCondNode)
        # else:
        #     breakpoint()
        #     raise Exception('Not take into considering')

        exprCondSrc1Node = {
            'id': nodeId,
            'text': 'condsrc1@'
        }
        nodeId += 1
        nodeMap.append(exprCondSrc1Node)
        edgeMap.append({
            'link': (exprCondSrc1Node['id'], exprCondNode['id']),
            'attr': 'Property'
        })
        src1 = node.src1
        if isinstance(src1, ExprLoc):
            nodeId = self.getExprLocGraph(nodeMap, edgeMap, nodeId, src1, exprCondSrc1Node)

        exprCondSrc2Node = {
            'id': nodeId,
            'text': 'condsrc2@'
        }
        nodeId += 1
        nodeMap.append(exprCondSrc2Node)
        edgeMap.append({
            'link': (exprCondSrc2Node['id'], exprCondNode['id']),
            'attr': 'Property'
        })
        src2 = node.src2
        if isinstance(src2, ExprLoc):
            nodeId = self.getExprLocGraph(nodeMap, edgeMap, nodeId, src2, exprCondSrc2Node)

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprCondNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprCondNode['id']),
                    'attr': 'parent'
                })

        return nodeId


    def getExprComposeGraph(self, nodeMap, edgeMap, nodeId, node: ExprCompose, parentNode=None, reverse=False):
        exprComposeNode = {
            'id': nodeId,
            'text': 'ExprCond'
        }
        nodeId += 1
        nodeMap.append(exprComposeNode)

        exprComposeArgNode = {
            'id': nodeId,
            'text': 'composearg@'
        }
        nodeId += 1
        nodeMap.append(exprComposeArgNode)
        edgeMap.append({
            'link': (exprComposeArgNode['id'], exprComposeNode['id']),
            'attr': 'Property'
        })

        for argn in node.args:
            if isinstance(argn, ExprId):
                nodeId = self.getExprIdGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprComposeArgNode)
            elif isinstance(argn, ExprInt):
                nodeId = self.getExprIntGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprComposeArgNode)
            elif isinstance(argn, ExprOp):
                nodeId = self.getExprOpGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprComposeArgNode)
            elif isinstance(argn, ExprSlice):
                nodeId = self.getExprSliceGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprComposeArgNode)
            elif isinstance(argn, ExprMem):
                nodeId = self.getExprMemGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprComposeArgNode)
            elif isinstance(argn, ExprCond):
                nodeId = self.getExprCondGraph(nodeMap, edgeMap, nodeId, argn, parentNode=exprComposeArgNode)
            # else:
            #     breakpoint()
            #     raise Exception('Not take into considering.')

        if parentNode:
            if not reverse:
                edgeMap.append({
                    'link': (exprComposeNode['id'], parentNode['id']),
                    'attr': 'parent'
                })
            else:
                edgeMap.append({
                    'link': (parentNode['id'], exprComposeNode['id']),
                    'attr': 'parent'
                })

        return nodeId

    @staticmethod
    def getNodeId(node):
        return hash(node) & 0xFFFFFFFFFFFFFFFF

    def serializeToGraph(self, nodeId=0, **kwargs):
        nodeCollect = []
        for node in self.nodes():
            assignNode = {
                'id': nodeId,
                'text': 'assign',
            }
            nodeId += 1

            # handle left side var
            lvar = node.var
            lsVarNodeMap = []
            lsVarEdgeMap = []
            if isinstance(lvar, ExprId):
                nodeId = self.getExprIdGraph(lsVarNodeMap, lsVarEdgeMap, nodeId, lvar, parentNode=assignNode, reverse=True)
            elif isinstance(lvar, ExprMem):
                nodeId = self.getExprMemGraph(lsVarNodeMap, lsVarEdgeMap, nodeId, lvar, parentNode=assignNode, reverse=True)

            # handle right side expression
            lbl, index, reg = node
            lblk = self._blocks[lbl]
            assign = lblk[index]

            rsExprNodeMap = []
            rsExprEdgeMap = []
            if index == -1:
                if not kwargs.get('config'):
                    continue
                if not kwargs.get('arch'):
                    continue
                publicConfig = kwargs.get('config')
                arch = kwargs.get('arch')
                callArguments = publicConfig['ABI'][arch]['callArguments']
                argMap = {reg: idx for idx, reg in enumerate(['None', ] + callArguments)}
                rexprText = 'FUNC_ARG_%d' % (argMap[reg.name])
                rexprNode = {
                    'id': nodeId,
                    'text': rexprText
                }
                nodeId += 1
                rsExprNodeMap.append(rexprNode)
                rsExprEdgeMap.append({
                    'link': (rexprNode['id'], assignNode['id']),
                    'attr': 'parent'
                })

            else:
                src = assign[reg]
                if isinstance(src, ExprId):
                    nodeId = self.getExprIdGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprOp):
                    nodeId = self.getExprOpGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprMem):
                    nodeId = self.getExprMemGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprCond):
                    nodeId = self.getExprCondGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprSlice):
                    nodeId = self.getExprSliceGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprInt):
                    nodeId = self.getExprIntGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprCompose):
                    nodeId = self.getExprComposeGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)
                elif isinstance(src, ExprLoc):
                    nodeId = self.getExprLocGraph(rsExprNodeMap, rsExprEdgeMap, nodeId, src, parentNode=assignNode)

            nodeCollect.append({
                'assign': assignNode,
                'nodehash':  self.nodeid(node),
                'lsVarNodeMap': lsVarNodeMap,
                'lsVarEdgeMap': lsVarEdgeMap,
                'rsExprNodeMap': rsExprNodeMap,
                'rsExprEdgeMap': rsExprEdgeMap
            })

            # print(lsVarNodeMap, lsVarEdgeMap)
            # print(rsExprNodeMap, rsExprEdgeMap)
            # print()

        graph = {
            'node': [],
            'edge': []
        }
        for src, dst in self.edges():
            srcHash = self.nodeid(src)
            dstHash = self.nodeid(dst)

            srcAssignNodeid = None
            for a in nodeCollect:
                if a['nodehash'] == srcHash:
                    srcAssignNodeid = a['assign']['id']
                    break

            dstAssignNodeid = None
            for b in nodeCollect:
                if b['nodehash'] == dstHash:
                    dstAssignNodeid = b['assign']['id']
                    break

            if srcAssignNodeid == None or dstAssignNodeid == None:
                continue

            graph['edge'].append({
                'link': (srcAssignNodeid, dstAssignNodeid),
                'attr': 'connect'
            })

        for tmpnode in nodeCollect:
            graph['node'].append(tmpnode['assign'])
            graph['node'].extend(tmpnode['lsVarNodeMap'])
            graph['node'].extend(tmpnode['rsExprNodeMap'])

            graph['edge'].extend(tmpnode['lsVarEdgeMap'])
            graph['edge'].extend(tmpnode['rsExprEdgeMap'])

        return graph
        # self.display(graph)

    def display(self, graph):
        import networkx as nx
        import matplotlib.pyplot as plt
        G = nx.Graph()
        for node in graph['node']:
            G.add_node(node["id"], text=node["text"])

        for edge in graph['edge']:
            G.add_edge(edge['link'][0], edge['link'][1])

        plt.figure(figsize=(24, 18))
        pos = nx.spring_layout(G)
        nx.draw_networkx_nodes(G, pos, node_color='lightblue',
                               node_size=500)
        nx.draw_networkx_edges(G, pos)
        labels = {node["id"]: node["text"] for node in graph['node']}
        nx.draw_networkx_labels(G, pos, labels)
        plt.axis('off')
        plt.show()

    def node2lines(self, node):
        lbl, index, reg = node
        lblk = self._blocks[lbl]
        assign = lblk[index]
        yield self.DotCellDescription(text="%s (%s) %.8X" % (lbl, index, assign.instr.offset if assign.instr else 0),
                                      attr={'align': 'center',
                                            'colspan': 2,
                                            'bgcolor': 'grey'})

        if index == -1:
            argMap = {reg: idx for idx, reg in enumerate(('NONE', 'RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'))}
            line = "%s = %s" % (reg, 'FUNC_ARG_%d' % (argMap[reg.name]))
        else:
            src = assign[reg]
            if isinstance(src, ExprOp) and hasattr(src, 'op') and src.op.startswith('call'):
                loc_key = src.args[0]
                fname = lblk.loc_db.get_location_names(loc_key.loc_key)
                if len(fname) == 0:
                    fsoffset = lblk.loc_db.get_location_offset(loc_key.loc_key)
                    fsname = 'func_%x' % fsoffset
                else:
                    fsname = fname[0]
                srcDesc = (src.op + '(' + fsname + ', ' + ', '.join([str(arg) for arg in src.args[1:]]) + ')')
                line = "%s = %s" % (reg, srcDesc)
            else:
                line = "%s = %s" % (reg, src)
        yield self.DotCellDescription(text=line, attr={})
        yield self.DotCellDescription(text="", attr={})

    def node2text(self, node):
        lbl, index, reg = node
        lblk = self._blocks[lbl]
        assign = lblk[index]
        if index == -1:
            argMap = {reg: idx for idx, reg in enumerate(('NONE', 'RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'))}
            line = "%s = %s" % (reg, 'FUNC_ARG_%d' % (argMap[reg.name]))
        else:
            src = assign[reg]
            if (isinstance(src, ExprOp)
                    and hasattr(src, 'op')
                    and src.op.startswith('call_func')
                    and isinstance(src.args[0], ExprLoc)
            ):
                loc_key = src.args[0]
                fname = lblk.loc_db.get_location_names(loc_key.loc_key)
                # if isinstance(fname, frozenset):
                #     breakpoint()
                if len(fname) == 0:
                    fsoffset = lblk.loc_db.get_location_offset(loc_key.loc_key)
                    fsname = 'func_%x' % fsoffset
                else:
                    fsname = list(fname)[0]
                srcDesc = (src.op + '(' + fsname + ', ' + ', '.join([str(arg) for arg in src.args[1:]]) + ')')
                line = "%s = %s" % (reg, srcDesc)
            else:
                line = "%s = %s" % (reg, src)
        return line


_REG_NAMES_x64 = [
    'rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rip', 'xmm0',  'xmm1',  'xmm2',  'xmm3', 'xmm4', 'xmm5', 'xmm6',
    'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14',
    'xmm15', 'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6',
    'st7', 'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6',
    'mm7', 'rflags', 'es', 'cs', 'ss', 'ds', 'fs', 'gs',
    '<none>', '<none>', 'fs.base', 'gs.base', '<none>', '<none>', 'tr', 'ldtr',
    'mxcsr', 'fcw', 'fsw'
]

ExprReg  = namedtuple('ExprReg', ('reg', 'callFrame'))
ExprLoca = namedtuple('ExprLoca', ('lowPC', 'highPC', 'expr'))
ExprFrameBase = namedtuple('ExprFrameBase', ('offset', 'callFrame'))

def transLocaToExpr(loca, callFrame, _REG_NAMES):
    exprList = []
    # if loca == None:
    #     breakpoint()
    for lo in loca:
        dwarfexpr = lo['dwarfExpr']
        if len(dwarfexpr) != 1:
            continue
        dwarfexpr = dwarfexpr[0]
        op_name = dwarfexpr['op_name']
        if op_name.startswith('DW_OP_GNU_entry_value'):
            continue
        if op_name.startswith('DW_OP_entry_value'):
            continue
        if op_name.startswith('DW_OP_breg'):
            continue

        # 先不考虑全局变量
        if op_name.startswith('DW_OP_addr'):
            continue

        if op_name.startswith('DW_OP_reg'):
            regnum = int(op_name[9:])
            if regnum > len(_REG_NAMES):
                continue
            reg = _REG_NAMES[regnum].upper()
            exprList.append(ExprLoca(lowPC=lo['lowPC'], highPC=lo['highPC'], expr=ExprReg(reg=reg, callFrame=callFrame)))

        if op_name.startswith('DW_OP_fbreg'):
            offset = dwarfexpr['args'][0]
            exprList.append(ExprLoca(lowPC=lo['lowPC'], highPC=lo['highPC'], expr=ExprFrameBase(offset=offset, callFrame=callFrame)))

    return exprList

# def cmpIntWithOverflow(offset, exprOp):
#     if exprOp.op == '+':
#         offset = offset
#         exprOffset = rexpr.args[1].arg
#         if offset == exprOffset:
#             return True
#
#         if exprOffset >= (1 << (IdSize - 1)):
#             exprOffset = exprOffset - (1 << IdSize)
#             if offset == exprOffset:
#                 return True
#     elif exprOp.op == '-': # -
#         offset = -offset
#         exprOffset = rexpr.args[1].arg
#         if -offset == exprOffset:
#             return True
#     else:
#         return False

def cmpExpr(FrameBaseReg, offset, rexpr):
    rexprDesc = str(rexpr)
    if not FrameBaseReg in rexprDesc:
        return False
    if offset == 0 and hasattr(rexpr, 'name') and rexpr.name == FrameBaseReg:
        return True
    if not isinstance(rexpr, ExprOp):
        return False
    if not rexpr.op in ('+', '-'):
        return False
    if not len(rexpr.args) == 2:
        return False
    if not hasattr(rexpr.args[0], 'name'):
        return False
    if not rexpr.args[0].name == FrameBaseReg:
        return False
    if isinstance(rexpr.args[1], ExprInt):
        if not hasattr(rexpr.args[1], 'size'):
            return False

        IdSize = rexpr.args[1].size
        if rexpr.op == '+':
            exprOffset = rexpr.args[1].arg
            if offset == exprOffset:
                return True

            if exprOffset >= (1 << (IdSize - 1)):
                exprOffset = exprOffset - (1 << IdSize)
                if offset == exprOffset:
                    return True
        else: # -
            exprOffset = rexpr.args[1].arg
            if -offset == exprOffset:
                return True
    elif isinstance(rexpr.args[1], ExprOp):
        if rexpr.op == '+':
            offset = offset
        else:
            offset = -offset

        subExpr = rexpr.args[1]
        if len(subExpr.args) < 1:
            return False

        if not isinstance(subExpr.args[0], ExprInt):
            return  False

        IdSize = subExpr.args[0].size
        if subExpr.op == '+':
            exprOffset = subExpr.args[0].arg
            if offset == exprOffset:
                return True

            if exprOffset >= (1 << (IdSize - 1)):
                exprOffset = exprOffset - (1 << IdSize)
                if offset == exprOffset:
                    return True
        elif subExpr.op == '-':
            exprOffset = subExpr.args[0].arg
            if -offset == exprOffset:
                return True
        else:
            return False
    return False

def appropriateRange(callFrame, fnStart, fnEnd):
    startFrame= {'cfa': {'offset':0, 'reg': 'dummyREG'}, 'pc': fnStart}
    endFrame = {'cfa': {'offset':0, 'reg': 'dummyREG'}, 'pc': fnEnd}
    for frame in callFrame:
        if fnStart == frame['pc']:
            startFrame = frame
        if fnEnd == frame['pc']:
            endFrame = frame

    addrs = [startFrame['pc'], endFrame['pc']]
    for frame in callFrame:
        addrs.append(frame['pc'])
    addrs.sort()

    max_gap = 0
    start_num = None
    end_num = None
    for i in range(1, len(addrs)):
        gap = addrs[i] - addrs[i - 1]
        if gap >= max_gap:
            max_gap = gap
            start_num = addrs[i - 1]
            end_num = addrs[i]

    returnFrame = callFrame[0]
    for frame in callFrame:
        if frame['pc'] == start_num:
            returnFrame = frame

    return returnFrame

def oldAlgoToCalRange(callFrame):
    max_offset = float('-inf')  # 初始化为负无穷大
    maxOffsetFrame = None
    for frame in callFrame:
        current_offset = frame['cfa']['offset']
        if current_offset > max_offset:
            max_offset = current_offset
            maxOffsetFrame = frame
        elif maxOffsetFrame and current_offset == max_offset and frame['cfa']['reg'] != maxOffsetFrame['cfa']['reg']:
            max_offset = current_offset
            maxOffsetFrame = frame
    return maxOffsetFrame

def evaluteTwoExpr(A, B):
    try:
        A = sympify(A)
        B = sympify(B)
    except:
        return False
    if A.equals(B):
        return True
    return False

def findDefNodeWithoutPCRange(varExpr, reachings, fnStart, fnEnd):
    defs = set()
    refs = set()

    # maxOffsetFrame = oldAlgoToCalRange(varExpr.expr.callFrame)
    # print(maxOffsetFrame)
    maxOffsetFrame = appropriateRange(varExpr.expr.callFrame, fnStart, fnEnd)
    # print(maxOffsetFrame)

    if isinstance(varExpr.expr, ExprReg):
        return defs, refs

    blocks = reachings.ircfg.blocks
    for blk in viewvalues(blocks):
        for index, assignblk in enumerate(blk):
            if assignblk.instr is None:
                continue
            assignblk_asm_addr = assignblk.instr.offset
            if assignblk_asm_addr < maxOffsetFrame['pc']:
                continue
            # if nextFrame and assignblk_asm_addr >= nextFrame['pc']:
            #     continue

            offset = varExpr.expr.offset + maxOffsetFrame['cfa']['offset']
            FrameBaseReg = maxOffsetFrame['cfa']['reg'].upper()
#》》》》》》》》》 REG tranformer
            for lvar, rexpr in viewitems(assignblk):
                equal = cmpExpr(FrameBaseReg, offset, rexpr)
                if equal:
                    iFoundOneRef = (blk.loc_key, index)
                    refs.add(iFoundOneRef)

            assignblk_reaching_defs = reachings.get_definitions(blk.loc_key, index)
            for reachdef in assignblk_reaching_defs:
                if not isinstance(reachdef, ExprMem):
                    continue
                equal = cmpExpr(FrameBaseReg, offset, reachdef.ptr)
                if equal:
                    iFoundOneDef = assignblk_reaching_defs[reachdef]
                    defs.update(iFoundOneDef)

    return defs, refs

def findDefNodeWithPCRange(varExpr, reachings, fnStart, fnEnd):
    defs = set()
    refs = set()
    blocks = reachings.ircfg.blocks
    for blk in viewvalues(blocks):
        for index, assignblk in enumerate(blk):
            assignblk_asm_addr = assignblk.instr.offset
            if not assignblk_asm_addr >= varExpr.lowPC or not assignblk_asm_addr < varExpr.highPC:
                continue
            assignblk_reaching_defs = reachings.get_definitions(blk.loc_key, index)

            if isinstance(varExpr.expr, ExprReg):
                # REG = ExprId(varExpr.expr.reg, 64)
                # REGDef = assignblk_reaching_defs.get(REG, set())
                # defs.update(REGDef)
                for key, values in assignblk_reaching_defs.items():
                    keyStr = key.__str__()
                    if keyStr != varExpr.expr.reg:
                        continue
                    defs.update(values)

            else:
                minDistance = float('inf')
                closesCfa = None
                for frame in varExpr.expr.callFrame:
                    if not assignblk_asm_addr > frame['pc']:
                        continue
                    distance = assignblk_asm_addr - frame['pc']
                    minDistance = distance if distance < minDistance else minDistance
                    closesCfa = frame['cfa']
                if not closesCfa:
                    continue
                offset = varExpr.expr.offset + closesCfa['offset']
                FrameBaseReg = closesCfa['reg'].upper()
                valStrExpr = '%s + %d' % (FrameBaseReg, offset)

                for lvar, rexpr in viewitems(assignblk):
                    rexprDesc = str(rexpr)
                    if not FrameBaseReg in  rexprDesc:
                        continue
                    if not isinstance(rexpr, ExprOp):
                        continue
                    if not rexpr.op in ('+', '-'):
                        continue
                    try:
                        valStrExprSympy = sympify(valStrExpr)
                        rexprDescSympy = sympify(rexprDesc)
                    except:
                        # print(valStrExpr, rexprDesc)
                        continue
                    if valStrExprSympy.equals(rexprDescSympy):
                        iFoundOneRef = (blk.loc_key, index)
                        refs.add(iFoundOneRef)

                assignblk_reaching_defs = reachings.get_definitions(blk.loc_key, index)
                for reachdef in assignblk_reaching_defs:
                    if not isinstance(reachdef, ExprMem):
                        continue
                    reachdefExpr = str(reachdef.ptr)
                    if not FrameBaseReg in  reachdefExpr:
                        continue
                    try:
                        valStrExprSympy = sympify(valStrExpr)
                        reachdefExprSympy = sympify(reachdefExpr)
                    except:
                        continue
                    if valStrExprSympy.equals(reachdefExprSympy):
                        iFoundOneDef = assignblk_reaching_defs[reachdef]
                        defs.update(iFoundOneDef)
    return defs, refs