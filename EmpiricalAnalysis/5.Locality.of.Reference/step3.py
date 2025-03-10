import os
import re
import json

from tqdm import tqdm

import logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)

def getFilesBySuffix(root, suffix):
    filePaths = []
    for root, dirs, files in os.walk(root):
        for file in files:
            if not file.endswith(suffix):
                continue
            filePaths.append(os.path.join(root, file))
    return filePaths

def match(MRs):
    for MRA in MRs:
        for MRB in MRs:
            MRA['memberInfo']['memberType'] = MRA['memberInfo']['memberType'].replace('const', '')
            MRA['memberInfo']['memberType'] = MRA['memberInfo']['memberType'].replace(' ', '')
            MRB['memberInfo']['memberType'] = MRB['memberInfo']['memberType'].replace('const', '')
            MRB['memberInfo']['memberType'] = MRB['memberInfo']['memberType'].replace(' ', '')
            if MRA['memberInfo']['typeName'] != MRB['memberInfo']['typeName']:
                continue
            if MRA['memberInfo']['memberOffset'] != MRB['memberInfo']['memberOffset']:
                continue
            if MRA['memberInfo']['memberType'] != MRB['memberInfo']['memberType']:
                continue
            if MRA['memberInfo']['memberType'] == '':
                continue
            if MRA['objectInfo']['objectType'] == MRB['objectInfo']['objectType']:
                continue
            if MRA['objectInfo']['objectType'] in MRB['objectInfo']['objectType']:
                continue
            if MRB['objectInfo']['objectType'] in MRA['objectInfo']['objectType']:
                continue
            # print(MRA['memberInfo']['memberType'])
            return True, MRA, MRB
    return False, None, None


def extractMemberRef(filePath):
    with open(filePath) as fp:
        data = json.load(fp)
    
    Collect = []
    for fnInfo in data:
        MRs = fnInfo['memberReference']
        if len(MRs) == 0:
            continue
        ret, MRA, MRB = match(MRs)
        if ret:
            Collect.append({
                'filePath': filePath.replace('.ea.exp4.json', ''),
                'fnName': fnInfo['functionName'],
                'fnAddr': fnInfo['functionStart'],
                'MRA': MRA,
                'MRB': MRB
            })

            # exit(-1)
        # for Ref in MR:
        #     memberInfo = Ref['memberInfo']
        #     objectInfo = Ref['objectInfo']
    return Collect

DATA_DIR = '/archive/lgy/TYDA/x86_64/O0'
DATA_DIR = '/archive/lgy/TYDA/x86_64/O0/dev-lang/python-3.9.13'
if __name__ == '__main__':
    expResultList = getFilesBySuffix(DATA_DIR, '.ea.exp4.json')
    logger.info('[+] Found *.ea.lab2.json %d' % (len(expResultList)))
    expResultList = sorted(
        expResultList,
        key=lambda x: os.path.getsize(x)
    )
    Collect = []
    for filePath in tqdm(expResultList):
        Collect.extend(extractMemberRef(filePath))

    with open('result.json', 'w') as fp:
        json.dump(Collect, fp, indent=2)
    # Collect = extractMemberRef(expResultList[10000])
    
