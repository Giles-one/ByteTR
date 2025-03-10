import os
import json
import tqdm

import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)

tagMap = {
    'DW_TAG_structure_type': 'struct',
    'DW_TAG_class_type': 'class',
    'DW_TAG_enumeration_type': 'enum',
    'DW_TAG_union_type': 'union',
    'DW_TAG_array_type': '[]',
    'DW_TAG_const_type': 'const', 
    'DW_TAG_pointer_type': '*',
    'DW_TAG_reference_type': '&',
    'DW_TAG_typedef': 'typedef',
    'DW_TAG_base_type': ''
}

def parseType2(typename, chain):
    if chain == None:
        return typename
    typedes = list()
    for c in chain:
        if c.get('typetag') not in list(tagMap.keys()):
            continue
        realName = tagMap[c.get('typetag')]

        if c.get('typetag') == 'DW_TAG_const_type':
            continue
        
        if c.get('typetag') == 'DW_TAG_typedef':
            continue

        if c.get('typetag') == 'DW_TAG_structure_type':
            typedes.append(realName)
            continue

        if c.get('typetag') == 'DW_TAG_enumeration_type':
            typedes.append(realName)
            break

        if c.get('typetag') == 'DW_TAG_union_type':
            typedes.append(realName)
            continue
        
        
        if c.get('typename'):
            typedes.append('%s %s' % (realName, c.get('typename')))
        else:
            typedes.append(realName)
    
    last = chain[-1]
    if not last.get('typename'):
        if last.get('typetag') in ('DW_TAG_structure_type', ):
            pass
        else:
            typedes.append('void')
    
    return ' '.join(typedes)


def parseType(typename, chain):
    if chain == None:
        return typename
    '''
    DW_TAG_structure_type    : struct
    DW_TAG_class_type        : class
    DW_TAG_enumeration_type  : enum
    DW_TAG_union_type        : union
    DW_TAG_array_type        : []
    '''
    isStruct = False
    isClass  = False
    isEnum   = False
    isUnion  = False
    isArray  = False
    for c in chain:
        if c.get('typetag') == 'DW_TAG_structure_type':
            isStruct = True
        if c.get('typetag') == 'DW_TAG_class_type':
            isClass = True
        if c.get('typetag') == 'DW_TAG_enumeration_type':
            isEnum = True
        if c.get('typetag') == 'DW_TAG_union_type':
            isUnion = True
        if c.get('typetag') == 'DW_TAG_array_type':
            isArray = True
    if isStruct:
        typename = 'struct %s' % typename
    if isClass:
        typename = 'class %s' % typename
    if isEnum:
        typename = 'enum %s' % typename
    if isUnion:
        typename = 'union %s' % typename
    if isArray:
        typename = '%s []' % typename

    return typename

def dedup():
    # ELFRoot = '/archive/lgy/TYDA/x86_64/O0'
    # ELFList = []
    # for root, dirs, files in os.walk(ELFRoot):
    #     for file in files:
    #         if not file.endswith('ea.exp1.jsonl'):
    #             continue
    #         filePath = os.path.join(root, file)
    #         ELFList.append(filePath)
    # logger.info('Found %d jsonl files.' % len(ELFList))

    # typeCollect = []
    # for filePath in tqdm.tqdm(ELFList):
    #     with open(filePath) as fp:
    #         for line in fp:
    #             item = json.loads(line)
    #             variableList = list()
    #             variableList.extend(item.get('variable'))
    #             variableList.extend(item.get('parameter'))
    #             for var in variableList:
    #                 typeCollect.append({'typename': var.get('DW_AT_type'), 'chain': var.get('DW_AT_type_chain')})
    # logger.info('Found %d variable.' % len(typeCollect))
    # with open("dedup.json", 'w') as fp:
    #     json.dump(typeCollect, fp)

    with open("dedup.json") as fp:
        typeCollect = json.load(fp)

    from collections import defaultdict
    typeSummary = defaultdict(int)
    for type in typeCollect:
        dedupType = parseType2(
            type.get('typename'), 
            type.get('chain')
        )
        typeSummary[dedupType] += 1

    sortedTypeSummary = sorted(typeSummary.items(), key=lambda x: x[1], reverse=True)
    with open("dedup.summary.json", "w") as fp:
        json.dump(sortedTypeSummary, fp, indent=2)

def zipsLaw():
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
    
    with open("variables.json", 'w') as fp:
        json.dump(typeCollect, fp, indent=2)
    
    from collections import defaultdict

    typeSummary = defaultdict(int)
    for type in typeCollect:
        typeSummary[type] += 1

    sortedTypeSummary = sorted(typeSummary.items(), key=lambda x: x[1], reverse=True)

    with open("zipfs.law.json", "w") as fp:
        json.dump(sortedTypeSummary, fp, indent=2)

    
def heapsLaw():
    with open("variables.json") as fp:
        typeCollect = json.load(fp)
    
    from collections import defaultdict
    typeSummary = defaultdict(int)
    heapsCollect = list()
    for idx, type in enumerate(typeCollect):
        typeSummary[type] += 1
        heapsCollect.append((idx + 1, len(typeSummary)))

    with open("heaps.law.json", "w") as fp:
        json.dump(heapsCollect, fp, indent=2)


if __name__ == '__main__':
    # zipsLaw()
    heapsLaw()
    # dedup()