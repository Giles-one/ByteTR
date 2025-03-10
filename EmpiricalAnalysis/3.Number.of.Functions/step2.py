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

# Map = defaultdict(lambda: defaultdict(int))

def main():
    expResultList = getFilesBySuffix(DATA_DIR, '.ea.exp2.1.jsonl')
    logger.info('[+] Found *.ea.lab2.1.jsonl %d' % (len(expResultList)))
    expResultList = sorted(
        expResultList,
        key=lambda x: os.path.getsize(x),
    )
    Map = defaultdict(int)

    pattern = r'^[av]\d+$'
    for filePath in tqdm.tqdm(expResultList[:]):
        with open(filePath) as fp:
            for line in fp:
                obj = json.loads(line)
                for lvar in obj.get('lvariable'):
                    lvarName = lvar.get('varName')
                    # if re.match(pattern, lvarName):
                    #     continue
                    lvarCallingDepth = lvar.get('callingDepth')
                    # lvarType = lvar.get('varType')
                    # Map[lvarCallingDepth][lvarType] += 1
                    Map[lvarCallingDepth] += 1
    
    sortedMap = sorted(Map.items(), key=lambda x: x[0])
    sortedMap = {key: value for key, value in sortedMap}
    
    with open('result.json', 'w') as fp:
        json.dump(sortedMap, fp, indent=2)
    # print(Map)

if __name__ == '__main__':
    main()