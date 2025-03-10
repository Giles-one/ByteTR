import os
import json
import argparse
import subprocess

from tqdm import tqdm
from elftools.elf.elffile import ELFFile

configPath = "config/binary.config.json"
publicConfigPath = "config/public.config.json"

def getFilesByDir(directory):
    global ELFSuffix
    filePaths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json') or file.endswith('.jsonl') or file.endswith('.log') or file.endswith('.i64'):
                continue
            if ELFSuffix in file:
                continue
            filePaths.append(os.path.join(root, file))
    return filePaths

def getMetaInfoByELF(elfPath):
    try:
        with open(elfPath, 'rb') as f:
            elf = ELFFile(f)
            return {
                'Machine': elf.get_machine_arch(),
                'Entry': hex(elf['e_entry']),
                'Type': elf['e_type'],
            }
    except Exception as e:
        print(f"Error processing {elfPath}: {str(e)}")
        return None

def isELFCPP(readelf, elfPath):
    try:
        result = subprocess.run(
            [readelf, '-d', elfPath],
            capture_output=True,
            text=True,
            check=True
        )
        return "libstdc++" in result.stdout
    
    except subprocess.CalledProcessError:
        return None

def getFileSize(filePath):
    return os.path.getsize(filePath)

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

    global ELFSuffix
    global stripELFSuffix
    
    ELFSuffix = publicConfig['suffix']['selectELFSuffix']
    stripELFSuffix = publicConfig['suffix']['selectStrippedELFSuffix']
    collect = list()
    
    filePaths = getFilesByDir(rawBinaryPath)
    filePaths =  sorted(
        filePaths,
        key=lambda file: os.path.getsize(file)
    )
    # breakpoint()
    for filePath in tqdm(filePaths[:]):
        # we don't like big ELF for memory limit. ):
        # Choose an appropriate value for your computer's memory
        fileSize = getFileSize(filePath)
        if fileSize > args.limit:
            continue
        
        metaInfo = getMetaInfoByELF(filePath)
        if not metaInfo:
            continue
        
        machine = metaInfo.get('Machine')
        if machine != publicConfig['arch'][arch]['alias']:
            continue
        
        ELFType = metaInfo.get('Type')
        if ELFType not in ('ET_DYN', 'ET_EXEC'):
            continue

        if isELFCPP(publicConfig['arch'][arch]['readelf'], filePath) != False:
            continue

        rawELFName   = filePath + ELFSuffix
        stripELFName = rawELFName + stripELFSuffix
        try:
            subprocess.run(
                ['cp', filePath, rawELFName], 
                check=True
            )
            subprocess.run(
                [publicConfig['arch'][arch]['strip'], rawELFName, "-o", stripELFName], 
                check=True
            )
        except:
            continue
        
        collect.append(rawELFName)
        if len(collect) > args.topk:
            break

def check():
    with open('ELF.json', 'r') as fp:
        Collect = json.load(fp)

    for ELF in Collect:
        ELFPath = ELF.get('ELF')
        ELFStripPath = ELF.get('StripELF')
        assert os.path.isfile(ELFPath)
        assert os.path.isfile(ELFStripPath)


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
        '--limit', 
        type=int, 
        default= 5 * 1024 * 1024, 
        help="Limit the size of items to process (Optional)"
    )
    parser.add_argument(
        '--topk', 
        type=int, 
        default=6000, 
        help="Select top k items (Optional)"
    )
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = argParse()
    main(args)
