import os
import re
import json
import tqdm

from collections import defaultdict

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

DATA_DIR = '/archive/lgy/TYDA/x86_64/O0'

def main():
    expResultList = getFilesBySuffix(DATA_DIR, '.ea.exp2.1.jsonl')
    logger.info('[+] Found *.ea.lab2.1.jsonl %d' % (len(expResultList)))
    expResultList = sorted(
        expResultList,
        key=lambda x: os.path.getsize(x),
    )

    collect = []
    for filePath in tqdm.tqdm(expResultList[:]):
        with open(filePath) as fp:
            for line in fp:
                obj = json.loads(line)
                nALL = len(obj.get('lvariable'))
                if nALL == 0:
                    continue
                nHit = 0
                for lvar in obj.get('lvariable'):
                    lvarCallingDepth = lvar.get('callingDepth')
                    if lvarCallingDepth > 1:
                        nHit += 1
                collect.append((nALL, nHit))

    with open('result.json', 'w') as fp:
        json.dump(collect, fp, indent=2)

if __name__ == '__main__':
    main()