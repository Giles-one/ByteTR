import os
import json
import tqdm

import logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    ELFRoot = '/archive/lgy/TYDA/x86_64/O0'
    ELFList = []
    for root, dirs, files in os.walk(ELFRoot):
        for file in files:
            if not file.endswith('ea.exp1.jsonl'):
                continue
            filePath = os.path.join(root, file)
            ELFList.append(filePath)
    logger.info('Found %d jsonl files.' % len(ELFList))

    typeCollect = []
    for filePath in tqdm.tqdm(ELFList):
        with open(filePath) as fp:
            for line in fp:
                item = json.loads(line)
                variableList = list()
                variableList.extend(item.get('variable'))
                variableList.extend(item.get('parameter'))
                for var in variableList:
                    typeCollect.append(var.get('DW_AT_type'))
    logger.info('Found %d variable.' % len(typeCollect))

    from collections import defaultdict
    typeSummary = defaultdict(int)
    for type in typeCollect:
        typeSummary[type] += 1

    sortedTypeSummary = sorted(typeSummary.items(), key=lambda x: x[1], reverse=True)
    with open("result.json", "w") as fp:
        json.dump(sortedTypeSummary, fp, indent=2)

if __name__ == '__main__':
    main()