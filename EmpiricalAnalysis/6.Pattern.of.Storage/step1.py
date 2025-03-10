import os
import json
import argparse
import multiprocessing

from tqdm import tqdm
from datetime import datetime
from collections import namedtuple

import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)

ExprReg  = namedtuple('ExprReg', ('reg', 'callFrame'))
ExprLoca = namedtuple('ExprLoca', ('lowPC', 'highPC', 'expr'))
ExprFrameBase = namedtuple('ExprFrameBase', ('offset', 'callFrame'))
ExprAddress  = namedtuple('ExprAddress', ('address', ))


def transLocaToExpr(loca):
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

        if op_name.startswith('DW_OP_addr'):
            return 'addressBased'

        if op_name.startswith('DW_OP_reg'):
            return 'regBased'
        
        if op_name.startswith('DW_OP_fbreg'):
            return 'stackBased'

    return 'idontkown'

def handleELF(elfInfo):
    collectInfo = []
    elfPath = elfInfo.get('path')
    for fnInfo in elfInfo.get('data'):
        fnName    = fnInfo.get('function_name')
        variable  = fnInfo.get('variable')
        parameter = fnInfo.get('parameter')
        variable.extend(parameter)
        for varInfo in variable:
            vname = varInfo.get('DW_AT_name')
            vtype = varInfo.get('DW_AT_type')
            vloca = varInfo.get('DW_AT_location')
            if not vname or not vtype or not vloca:
                continue
            tloca = transLocaToExpr(vloca)
            collectInfo.append({
                'ELF': elfPath,
                'fnName': fnName,
                'vname': vname,
                'vtype': vtype,
                'tloca': tloca
            })
    return collectInfo

def worker(ELFPath, saveIO):
    with open(ELFPath) as fp:
        elfInfo = json.load(fp)
    
    collectInfo = handleELF(elfInfo)
    
    for cinfo in collectInfo:
        saveIO.write(json.dumps(cinfo) + '\n')
        saveIO.flush()
    
    # try:
    #     handleELF(ELFPath)
    # except Exception as e:
    #     return f"Error processing ELF: {str(e)}"

def speedup(ELFCollect):
    numCores = 40
    pool = multiprocessing.Pool(processes=numCores)

    list(tqdm(pool.imap_unordered(worker, ELFCollect), total=len(ELFCollect)))
    pool.close()
    pool.join()


def main():
    ELFList = []

    OPTI = 'O3'
    rawBinaryPath = f'/archive/lgy/TYDA/x86_64/{OPTI}'
    for root, dirs, files in os.walk(rawBinaryPath):
        for file in files:
            if not file.endswith('.var.json'):
                continue
            filePath = os.path.join(root, file)
            ELFList.append(filePath)
    
    logger.info('Found summary info ** %d **.' % (len(ELFList)))
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f'result.{OPTI}.{timestamp}.jsonl'

    with open(filename, 'w') as fp:
        for ELFPath in tqdm(ELFList):
            worker(ELFPath, fp)

if __name__ == '__main__':
    main()

'''
for OPTI in O0 O1 O2 O3; do
    echo ======= $OPTI ==========;
    jq '.tloca' result.$OPTI.* | sort | uniq -c;
done

jq '.tloca' result.O1.2024-12-13_15-23-42.jsonl | sort | uniq -c
 509245 "addressBased"
 684538 "idontkown"
12230606 "regBased"
1956456 "stackBased"
'''