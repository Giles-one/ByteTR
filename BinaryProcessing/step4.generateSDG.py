import os
import json
import logging
import argparse
import multiprocessing

from math import fabs

from tqdm import tqdm
from future.utils import viewitems

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB

from miasm.ir.ir import AssignBlock, IRBlock
from miasm.analysis.data_flow import AssignblkNode
from miasm.analysis.data_flow import DiGraphDefUse, ReachingDefinitions

from utils.helper import DiGraphSV
from utils.helper import transLocaToExpr
from utils.helper import findDefNodeWithoutPCRange, findDefNodeWithPCRange

logger = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
logger.addHandler(console_handler)
logger.setLevel(logging.ERROR)

POSIXLibcPath = 'utils/POSIX.json'
with open(POSIXLibcPath) as fp:
    POSIXLibc = json.load(fp)

def getFunctionDefUseAndReachings(fnInfo):
    fnStart = fnInfo.get('functionLowPC')
    fnEnd   = fnInfo.get('functionHighPC')
    ELFPath = fnInfo.get('ELF')

    StripELFPath = ELFPath + '.strip'
    if not os.path.isfile(StripELFPath):
        logger.error('Error %s not found' % (StripELFPath))
        return

    loc_db = LocationDB()
    with open(StripELFPath, "rb") as fdesc:
        cont = Container.from_stream(
            fdesc, addr=0,
            loc_db=loc_db,
        )

    # Instance the arch-dependent machine
    machine = Machine(cont.arch)
    mn, dis_engine = machine.mn, machine.dis_engine
    mdis = dis_engine(cont.bin_stream, loc_db=cont.loc_db)

    # configure disasm engine
    mdis.dontdis_retcall = False
    mdis.blocs_wd = None
    mdis.dont_dis_nulstart_bloc = True
    mdis.follow_call = False

    # Main disasm loop work
    addr = fnStart
    job_done = set([fnEnd, ])
    asmcfg = mdis.dis_multiblock(addr, job_done=job_done)

    # modeling call instr
    class LifterDelModCallStack(machine.lifter_model_call):
        def call_effects(self, addr, instr):
            assignblks, extra = super(LifterDelModCallStack, self).call_effects_systemV(addr, instr)
            out = []
            for assignblk in assignblks:
                dct = dict(assignblk)
                dct = {
                    dst: src for (dst, src) in viewitems(dct) if dst != self.sp
                }
                out.append(AssignBlock(dct, assignblk.instr))
            return out, extra

    # Bonus, generate IR graph
    lifter = machine.lifter(mdis.loc_db)
    lifter_model_call = LifterDelModCallStack(mdis.loc_db)

    ircfg_model_call = lifter.new_ircfg()
    for block in asmcfg.blocks:
        lifter_model_call.add_asmblock_to_ircfg(block, ircfg_model_call)

    global publicConfig, arch
    callArguments = publicConfig['ABI'][arch]['callArguments']
    callerPreserved = publicConfig['ABI'][arch]['callerPreserved']
    reachings = ReachingDefinitions(ircfg_model_call, callArguments=callArguments, callerPreserved=callerPreserved)
    defuse = DiGraphDefUse(reachings, deref_mem=True)
    return reachings, defuse


def handleELF(elfInfo):
    ELFPath = elfInfo.get('ELF')
    ELFStripPath = ELFPath + selectStrippedELFSuffix
    defuseStore = {}
    global  publicConfig, arch
    for idx, fnInfo in enumerate(elfInfo.get('function')):
        elf   = fnInfo.get('ELF')
        fname = fnInfo.get('functionName')
        faddr = fnInfo.get('functionLowPC')

        logger.info(
            '[%d/%d] processing function %s@%s' % (
                idx + 1, len(elfInfo.get('function')),
                fname, elf
            )
        )
        # try:
        reachings, defuse = getFunctionDefUseAndReachings(fnInfo)
        # except:
        #     continue
        defuseStore[faddr] = (reachings, defuse)

    for fnInfo in elfInfo.get('function'):
        fnAddr    = fnInfo.get('functionLowPC')
        fnEnd     = fnInfo.get('functionHighPC')
        callFrame = fnInfo.get('callFrame')
        variable  = fnInfo.get('variable')
        parameter = fnInfo.get('parameter')
        variable.extend(parameter)
        allCount = 0
        successCount = 0
        THRESHOLD = 1
        for varInfo in variable:
            vname = varInfo.get('name')
            vtype = varInfo.get('type')
            vloca = varInfo.get('loca')
            allCount += 1

            if vloca == None:
                continue
            # try:
            # with open('/tmp/a', 'w') as fp:
            if True:
                varExprs = transLocaToExpr(vloca, callFrame, publicConfig['REG'][arch])
                defuseapck = defuseStore.get(fnAddr)
                if not defuseapck:
                    continue
                reaching, defuse = defuseapck

                WhereItRef = set()
                WhereItDefine = set()
                for varExpr in varExprs:
                    if varExpr.lowPC == -1:
                        defs, refs = findDefNodeWithoutPCRange(varExpr, reaching, fnAddr, fnEnd)
                    else:
                        defs, refs = findDefNodeWithPCRange(varExpr, reaching, fnAddr, fnEnd)
                    WhereItDefine.update(defs)
                    WhereItRef.update(refs)

                if len(WhereItDefine) + len(WhereItRef) == 0:
                    continue

                defsubgraph = DiGraphSV(WhereItDefine, defuse)
                if len(WhereItRef) > 0:
                    refsubgraph = DiGraphSV(WhereItRef, defuse)
                    defsubgraph.merge(refsubgraph)

                # open('a.dot', 'w').write(defsubgraph.dot())
                # mainGraph = defsubgraph.serializeForStorage()

                if len(defsubgraph._nodes) < THRESHOLD * 3:
                    continue
                graphForSave = defsubgraph.serializeToGraph(0)

                subs = defsubgraph.called_sub_functions()
                subs = list(subs)
                for sub in subs[:THRESHOLD]:
                    assignNode, argExprId, subfnAddr, opnode = sub
                    subReachings, subDefUse = defuseStore.get(subfnAddr, (None, None))
                    if subDefUse:
                        loc = list(subDefUse._blocks.keys())[0]
                        headnode  = AssignblkNode(loc, -1, argExprId)
                        headBlock = {headnode}

                        subfnSubGraph = DiGraphSV(headBlock, subDefUse, headsBlocks=True)

                        nodeIdHash = DiGraphSV.getNodeId(opnode)
                        peerNode = None
                        for tmpNode in graphForSave['node']:
                            tmpNodeText = tmpNode['text']
                            if not tmpNodeText.startswith('op@call_func_arg'):
                                continue
                            tmpNodeHashText = tmpNodeText.split('@')[-1]
                            tmpNodeHash = int(tmpNodeHashText)
                            if tmpNodeHash == nodeIdHash:
                                peerNode = tmpNode
                                break

                        if not peerNode:
                            continue

                        # peerNode -> internNode
                        internNode = {
                            'id': len(graphForSave['node']),
                            'text': 'internal_call'
                        }
                        graphForSave['node'].append(internNode)
                        graphForSave['edge'].append({
                            'link': (peerNode['id'], internNode['id']),
                            'attr': 'intern'
                        })

                        startId = len(graphForSave['node'])
                        subGraphForSave = subfnSubGraph.serializeToGraph(startId, config=publicConfig, arch=arch)
                        if len(subGraphForSave['node']) == 0:
                            continue
                    
                        graphForSave['node'].extend(subGraphForSave['node'])
                        graphForSave['edge'].extend(subGraphForSave['edge'])

                        graphForSave['edge'].append({
                            'link': (internNode['id'], startId),
                            'attr': 'intern'
                        })

                    else:
                        externFnName = next((fnanem for fnanem, fnaddr in elfInfo.get('extern').items() if fabs(fnaddr-subfnAddr) <= 4), None)
                        if not externFnName:
                            continue

                        nodeIdHash = DiGraphSV.getNodeId(opnode)
                        peerNode = None
                        for tmpNode in graphForSave['node']:
                            tmpNodeText = tmpNode['text']
                            if not tmpNodeText.startswith('op@call_func_arg'):
                                continue
                            tmpNodeHashText = tmpNodeText.split('@')[-1]
                            tmpNodeHash = int(tmpNodeHashText)
                            if tmpNodeHash == nodeIdHash:
                                peerNode = tmpNode
                                break
                        if not peerNode:
                            continue

                        # peerNode -> externNode
                        narg = int(peerNode['text'].split('@')[1][-1])
                        externNode = {
                            'id': len(graphForSave['node']),
                            'text': 'external_call'
                        }
                        graphForSave['node'].append(externNode)
                        graphForSave['edge'].append({
                            'link': (peerNode['id'], externNode['id']),
                            'attr': 'extern'
                        })
                        POSIXSig = POSIXLibc.get(externFnName)
                        if POSIXSig:
                            rettype, paramtype = POSIXSig
                            if len(paramtype) < narg:
                                externtext = 'void'
                            else:
                                externtext = paramtype[narg - 1]
                        else:
                            externtext = 'unknown'
                        externFnNode = {
                            'id': len(graphForSave['node']),
                            'text': 'extern_type@%s' % (externtext)
                        }
                        graphForSave['node'].append(externFnNode)
                        graphForSave['edge'].append({
                            'link': (externNode['id'], externFnNode['id']),
                            'attr': 'extern_func'
                        })
            # except:
            #     logger.error('%s %x %s %s serializeForStorage Error' % (ELFStripPath, fnAddr, vname, vtype))
            #     continue

            successCount += 1
            varInfo['graph'] = graphForSave
        logger.info('Variable success rate %.2f' % (successCount / allCount))

    saveTo = ELFStripPath + savedInfoSuffix
    with open(saveTo, 'w') as fp:
        json.dump(elfInfo, fp, indent=2)

def worker(inItem):
    jsonPath = inItem.get('sum')

    with open(jsonPath) as fp:
        ELF = json.load(fp)
    handleELF(ELF)

def workerWithTimeout(item):
    try:
        return worker(item)
    except Exception as e:
        # return f"Error processing item: {str(e)}"
        jsonPath = item.get('sum')
        with open("failed.log", "a") as log_file:
            log_file.write(f"Error processing {jsonPath}: {str(e)}\n")
        logger.error(f"Error processing {jsonPath}: {str(e)}")


def main_old():
    with open('ELF.json', 'r') as fp:
        elfCollect = json.load(fp)

    elfCollect =  sorted(
        elfCollect,
        key=lambda item: os.path.getsize(item['StripELF'])
    )
    for elfInfo in elfCollect[:10]:
        worker(elfInfo)

def speedup(elfCollect, timeoutSeconds=600):
    elfCollect =  sorted(
        elfCollect,
        key=lambda item: os.path.getsize(item['StripELF'])
    )
    numCores = 80
    pool = multiprocessing.Pool(processes=numCores)

    results = []
    for item in elfCollect:
        results.append(pool.apply_async(workerWithTimeout, (item,)))

    processedResults = []
    for result in tqdm(results, total=len(elfCollect)):
        try:
            processedResults.append(result.get(timeout=timeoutSeconds))
        except multiprocessing.TimeoutError:
            processedResults.append("Task timed out")
        except Exception as e:
            processedResults.append(f"Error: {str(e)}")

    pool.close()
    pool.join()

def argParse():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--arch', 
        type=str, 
        required=True, 
        help="Architecture type"
    )
    parser.add_argument(
        '--opt', 
        type=str, 
        required=True, 
        help="Optimization Method"
    )
    parser.add_argument(
        '--nproc', 
        type=int, 
        default= 112, 
        help="Limit the size of items to process (Optional)"
    )
    args = parser.parse_args()
    return args

configPath = "config/binary.config.json"
publicConfigPath = "config/public.config.json"

def main(args):
    assert os.path.exists(configPath), 'Config file does not exists. %s' % configPath
    with open(configPath, 'r') as fp:
        config = json.load(fp)

    global arch, opt
    arch = args.arch
    assert arch in config['arch']
    opt  = args.opt
    assert  opt in config['opt']
    
    rawBinaryPath = os.path.join(config['TYDA'], arch, opt)
    assert os.path.exists(rawBinaryPath), 'Arch raw binary not exists. %s' % rawBinaryPath

    global publicConfig
    assert os.path.exists(publicConfigPath), "public config not exists. %s" % publicConfigPath
    with open(publicConfigPath) as fp:
        publicConfig = json.load(fp)

    global selectELFSuffix
    global summaryInfoSuffix
    global selectStrippedELFSuffix
    global variableInfoSuffix
    global funcionFrameInfoSuffix
    global savedInfoSuffix

    selectELFSuffix = publicConfig['suffix']['selectELFSuffix']
    summaryInfoSuffix = publicConfig['suffix']['summaryInfoSuffix']
    selectStrippedELFSuffix = publicConfig['suffix']['selectStrippedELFSuffix']
    variableInfoSuffix = publicConfig['suffix']['variableInfoSuffix']
    funcionFrameInfoSuffix = publicConfig['suffix']['funcionFrameInfoSuffix']
    savedInfoSuffix = publicConfig['suffix']['savedInfoSuffix']

    ELFList = []
    for root, dirs, files in os.walk(rawBinaryPath):
        for file in files:
            if not file.endswith(selectELFSuffix):
                continue
            filePath = os.path.join(root, file)
            strippedPeer = filePath + selectStrippedELFSuffix
            if not os.path.exists(strippedPeer):
                continue
            variableInfoPerr = filePath + variableInfoSuffix
            if not os.path.exists(variableInfoPerr):
                continue
            functionFrameInfoPerr = filePath + funcionFrameInfoSuffix
            if not os.path.exists(functionFrameInfoPerr):
                continue
            summaryInfoPeer = filePath + summaryInfoSuffix
            if not os.path.exists(summaryInfoPeer):
                continue
            ELFList.append({
                'ELF': filePath,
                'var': variableInfoPerr,
                'cfi': functionFrameInfoPerr,
                'sum': summaryInfoPeer,
                'StripELF': strippedPeer,
            })
    
    logger.info('Found summary info ** %d **.' % (len(ELFList)))
    speedup(ELFList)

if __name__ == '__main__':
    args = argParse()
    main(args)
