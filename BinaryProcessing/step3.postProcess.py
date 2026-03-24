import os
import json
import argparse
import multiprocessing


import sys
# FUCK the pwntools module for hijacking my arguments. ):
argv = sys.argv[:]

import pwn
from tqdm import tqdm

pwn.context.log_level = 'error'
import logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)


def getJsonFiles(root):
    fileList = list()
    for root, dirs, files in os.walk(root):
        for file in files:
            if not file.endswith('.elf'):
                continue
            elfPath    = os.path.join(root, file)
            elfVarJson = os.path.join(root, file + '.var.json')
            elfCfiJson = os.path.join(root, file + '.cfi.json')
            if not os.path.isfile(elfVarJson):
                continue
            if not os.path.isfile(elfCfiJson):
                continue
            fileList.append({'elf': elfPath, 'var': elfVarJson, 'cfi': elfCfiJson})
    return fileList

def parseDataType(typechain):
    array   = False
    pointer = False
    struct  = False
    base    = False

    typeDesc= typechain[-1]

    for t in typechain[:-1]:
        if t == 'DW_TAG_array_type':
            array = True
        if t == 'DW_TAG_base_type':
            base = True
        if t == 'DW_TAG_pointer_type':
            pointer = True
        if t == 'DW_TAG_structure_type':
            struct = True

    if array:
        return 'array'

    if base:
        typename = typeDesc.split('@')[0]
        label2typename = {
            'i8'    : {'char', 'signed char'},
            'u8'    : {'unsigned char'},
            'i16'   : {'short int', 'short signed int', 'signed short int'},
            'u16'   : {'short unsigned int', 'unsigned short int'},
            'i32'   : {'int', 'signed int'},
            'u32'   : {'unsigned int'},
            'i64'   : {'long int', 'long long int', 'long signed int', 'long long signed int'},
            'u64'   : {'long long unsigned int', 'unsigned long', 'long unsigned int'},
            'float' : {'float'},
            'double': {'double'},
        }
        label = next((key for key, value in label2typename.items() if typename in value), None)
        if not label:
            return 'unknown'
        if pointer:
            return label + "*"
        else:
            return label

    if struct:
        if typeDesc.split('@')[1] == '':
            return 'unknown'
        if pointer:
            return 'struct*'
        else:
            return 'struct'

    if pointer and typeDesc.split('@')[0] == '':
        return 'void*'

    return 'unknown'


def postProcessOneJson(ELFPath, elfVarJsonPath, elfCfiJsonPath):
    assert os.path.isfile(elfVarJsonPath), 'Err %s is not a file.' % (elfVarJsonPath)
    assert os.path.isfile(elfCfiJsonPath), 'Err %s is not a file.' % (elfCfiJsonPath)

    with open(elfVarJsonPath, 'r') as fp:
        elfVarInfo = json.load(fp)
    with open(elfCfiJsonPath, 'r') as fp:
        elfCfiInfo = json.load(fp)

    Collect = []
    ELFPath = elfVarInfo['path']
    for fnInfo in elfVarInfo['data']:
        functionName = fnInfo.get('function_name')
        if not functionName:
            continue
        functionName = functionName.replace('"', "")
        fnAttr = fnInfo['function_attr']
        skip = False
        for key in ('DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_decl_file', 'DW_AT_decl_line'):
            if not key in fnAttr.keys():
                skip = True
                break
        if skip:
            continue

        fnLocPC  = int(fnAttr['DW_AT_low_pc'])
        fnHighPC = int(fnAttr['DW_AT_high_pc']) + fnLocPC
        peerCfiInfo = next(
            (fnCfiInfo['items']
            for fnCfiInfo in elfCfiInfo
            if fnCfiInfo['lowPC'] == fnLocPC and fnCfiInfo['highPC'] == fnHighPC),
            None
        )
        if not peerCfiInfo:
            # print('==========> %s@%s does not find a cfi' % (fnInfo['function_name'], ELFPath))
            continue

        fnInfo['callFrame'] = peerCfiInfo
        fnInfo['ELF'] = ELFPath
        oneFunctionInfo = {
            'ELF'            : ELFPath,
            'functionName'   : functionName,
            'functionLowPC'  : fnLocPC,
            'functionHighPC' : fnHighPC,
            'callFrame'      : peerCfiInfo,
            'parameter'      : [],
            'variable'       : []
        }

        for variable in fnInfo.get('variable'):
            vname = variable.get('DW_AT_name')
            if not vname:
                continue
            vname = vname.replace('"', "")

            vtype = parseDataType(variable.get('DW_AT_type'))
            # assert vtype in labels
            oneFunctionInfo['variable'].append({
                'name': vname,
                'type': vtype,
                'loca': variable.get('DW_AT_location')
            })
        for parameter in fnInfo.get('parameter'):
            vname = parameter.get('DW_AT_name')
            if not vname:
                continue
            vname = vname.replace('"', "")

            vtype = parseDataType(parameter.get('DW_AT_type'))
            # assert vtype in labels
            oneFunctionInfo['parameter'].append({
                'name': vname,
                'type': vtype,
                'loca': parameter.get('DW_AT_location')
            })
        Collect.append(oneFunctionInfo)

    elf = pwn.ELF(ELFPath, checksec=False)
    plt = elf.plt
    ELFCollect = {
        'ELF'      : ELFPath,
        'function' : Collect,
        'extern'   : plt
    }
    
    global summaryInfoSuffix
    saveTo = ELFPath + summaryInfoSuffix
    with open(saveTo, 'w') as fp:
        json.dump(ELFCollect, fp, indent=2)

def main_old():
    TARGET = '../demo/Tinyhttpd'
    saveTo = './save.json'
    elfInfoList = getJsonFiles(TARGET)
    logger.info('Found %d json files' % (len(elfInfoList)))

    Collect = []
    for elfInfo in elfInfoList:
        elfVarJsonPath = elfInfo['var']
        elfCfiJsonPath = elfInfo['cfi']
        oneCollect = postProcessOneJson(elfVarJsonPath, elfCfiJsonPath)
        Collect.append(oneCollect)

    logger.info('Collect %d data.' % (len(Collect)))
    with open(saveTo, 'w') as fp:
        json.dump(Collect, fp, indent=2)
    logger.info('saveTo %s' % (saveTo))

def worker(ELF):
    try:
        ELFPath = ELF.get('ELF')
        elfVarJsonPath = ELF.get('var')
        elfCfiJsonPath = ELF.get('cfi')
        if ELFPath is None:
            raise KeyError(f"'ELF' key not found in {ELF}")
        postProcessOneJson(ELFPath, elfVarJsonPath, elfCfiJsonPath)

    except Exception as e:
        with open("failed.log", "a") as log_file:
            log_file.write(f"Error processing {ELFPath}: {str(e)}\n")
        logger.error(f"Error processing {ELFPath}: {str(e)}")


def speedup(ELFCollect):
    numCores = 112
    pool = multiprocessing.Pool(processes=numCores)

    list(tqdm(pool.imap_unordered(worker, ELFCollect), total=len(ELFCollect)))
    pool.close()
    pool.join()

def updateELFJson():
    collect = []
    for root, dirs, files in os.walk(dstDir):
        for file in files:
            if not file.endswith('.elf'):
                continue
            filePath = os.path.join(root, file)
            stripFilePath = os.path.join(root, file + '.strip')
            VarFilePath = os.path.join(root, file + '.var.json')
            CfiFilePath = os.path.join(root, file + '.cfi.json')
            SumFilePath = os.path.join(root, file + '.sum.json')

            if not os.path.exists(stripFilePath):
                continue
            if not os.path.exists(VarFilePath):
                continue
            if not os.path.exists(CfiFilePath):
                continue
            if not os.path.exists(SumFilePath):
                continue

            collect.append({
                'ELF'         : filePath,
                'StripELF'    : stripFilePath,
                'Machine'     : 'x64',
                'var'         : VarFilePath,
                'cfi'         : CfiFilePath,
                'sum'         : SumFilePath,
            })
    print('Found %d ELF.' % (len(collect)))
    with open('ELF.json', 'w') as fp:
        json.dump(collect, fp, indent=2)

def argParse(argv):
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
    args = parser.parse_args(argv[1:])
    return args

configPath = "config/binary.config.json"
publicConfigPath = "config/public.config.json"

def main(args):
    assert os.path.exists(configPath), 'Config file does not exists. %s' % configPath
    with open(configPath, 'r') as fp:
        config = json.load(fp)
    arch = args.arch
    assert arch in config['arch']
    opt  = args.opt
    assert  opt in config['opt']
    
    rawBinaryPath = os.path.join(config['TYDA'], arch, opt)
    assert os.path.exists(rawBinaryPath), 'Arch raw binary not exists. %s' % rawBinaryPath

    assert os.path.exists(publicConfigPath), "public config not exists. %s" % publicConfigPath
    with open(publicConfigPath) as fp:
        publicConfig = json.load(fp)

    global selectELFSuffix
    global summaryInfoSuffix
    global selectStrippedELFSuffix
    global variableInfoSuffix
    global funcionFrameInfoSuffix

    selectELFSuffix = publicConfig['suffix']['selectELFSuffix']
    summaryInfoSuffix = publicConfig['suffix']['summaryInfoSuffix']
    selectStrippedELFSuffix = publicConfig['suffix']['selectStrippedELFSuffix']
    variableInfoSuffix = publicConfig['suffix']['variableInfoSuffix']
    funcionFrameInfoSuffix = publicConfig['suffix']['funcionFrameInfoSuffix']

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
            ELFList.append({
                'ELF': filePath,
                'var': variableInfoPerr,
                'cfi': functionFrameInfoPerr
            })

    logger.info('Collect ELF file of ** %d **' % (len(ELFList)))
    speedup(ELFList[:5000])

if __name__ == '__main__':
    args = argParse(argv)
    main(args)