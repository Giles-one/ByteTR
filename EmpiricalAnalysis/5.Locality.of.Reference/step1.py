import os
import re
import json

from tqdm import tqdm
from cxxfilt import demangle
from collections import defaultdict

import multiprocessing

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

def extractMemberRef(filePath):
    with open(filePath) as fp:
        data = json.load(fp)
    
    Collect = []
    for fnInfo in data:
        MR = fnInfo['memberReference']
        if len(MR) == 0:
            continue
        Collect.extend(MR)
        # for Ref in MR:
        #     memberInfo = Ref['memberInfo']
        #     objectInfo = Ref['objectInfo']
    return Collect

DATA_DIR = '/archive/lgy/TYDA/x86_64/O0'
if __name__ == '__main__':
    expResultList = getFilesBySuffix(DATA_DIR, '.ea.exp4.json')
    logger.info('[+] Found *.ea.lab2.json %d' % (len(expResultList)))
    expResultList = sorted(
        expResultList,
        key=lambda x: os.path.getsize(x)
    )
    with open('result.jsonl', 'w') as fp:
        for filePath in tqdm(expResultList):
            Collect = extractMemberRef(filePath)
            if len(Collect) == 0:
                continue
            for Ref in Collect:
                fp.write(json.dumps(Ref) + '\n')

    # breakpoint()
    # for filePath in expResultList:
