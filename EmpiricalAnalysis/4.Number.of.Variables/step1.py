import os
import re
import json

from tqdm import tqdm
from cxxfilt import demangle
from collections import defaultdict

import multiprocessing

import logging
logging.basicConfig(
    level=logging.ERROR,
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

def splitString(inputString):
    delimiters = r'[ ,.!?;"\'()\[\]{}<>&*+-]+'
    tokens = re.split(delimiters, inputString)
    tokens = [token for token in tokens if token]
    return tokens


def processFnInfo(fnInfo):
    callRelation = fnInfo.get('call')
    fnInfo['lvariable'] = [
        lvar 
        for lvar in fnInfo.get('lvariable') 
        if lvar.get('varName').strip()
    ]
    varUsedAsArgMap = {
        lvar.get('varName'): set()
        for lvar in fnInfo.get('lvariable')
    }
    for call in callRelation:
        argExprs = call.get('argsExpr')
        for idx, argExpr in enumerate(argExprs):
            for key, value in varUsedAsArgMap.items():
                if key in splitString(argExpr):
                    value.add((call.get('calledName'), idx))
    
    parameters = [para.get('varName') for para in fnInfo.get('parameter')]
    for lvar in fnInfo.get('lvariable'):
        lvarName = lvar.get('varName')
        usedAsArg = varUsedAsArgMap.get(lvarName, set())
        lvar['usedAsArg'] = list(usedAsArg)
        lvar['isParam'] = lvarName in parameters

    fnInfo['parameter'] = parameters

def anaysisCallChian(callInfo):
    graph = defaultdict(set)

    for fnInfo in callInfo:
        paramMap = {
            param: idx
            for idx, param in enumerate(fnInfo.get('parameter'))
        }
        for lvar in fnInfo.get('lvariable'):
            if lvar.get('isParam'):
                paramIdx = paramMap[lvar.get('varName')]
                node = (fnInfo.get('functionName'), paramIdx)
                graph[node].update(lvar.get('usedAsArg'))

    def findAllPaths(graph):
        NPATH_THRESHOLD = 200
        def dfsSearch(currentVertex, visitedSet, currentPath, allPaths):
            if len(allPaths) > NPATH_THRESHOLD:
                return
            
            currentPath.append(currentVertex)
            visitedSet.add(currentVertex)
            isEnd = True  # Assume it's an end path unless we find an unvisited next vertex

            if currentVertex in graph:
                for nextVertex in graph[currentVertex]:
                    if nextVertex not in visitedSet:
                        isEnd = False  # If we find an unvisited next vertex, it's not an end path
                        dfsSearch(nextVertex, visitedSet, currentPath.copy(), allPaths)

            if isEnd:  # Only add the path if it's an end path
                allPaths.append(currentPath.copy())

            visitedSet.remove(currentVertex)

        vertexPaths = {}
        for startVertex in graph:
            visitedSet = {startVertex}
            allPaths = []
            dfsSearch(startVertex, visitedSet, [], allPaths)
            vertexPaths[startVertex] = allPaths

        return vertexPaths
    Paths = findAllPaths(graph)

    CallingSpread = defaultdict(set)
    for start, Path in Paths.items():
        for path in Path:
            for node in path:
                CallingSpread[start].add(node[0])
    # CallingDepth = {
    #     key:len(value)
    #     for key, value in CallingSpread.items()
    # }
    # CallingSpread = dict(CallingSpread)
    for fnInfo in callInfo:
        paramMap = {
            param: idx
            for idx, param in enumerate(fnInfo.get('parameter'))
        }
        for lvar in fnInfo.get('lvariable'):
            if lvar.get('isParam'):
                paramIdx = paramMap[lvar.get('varName')]
                node = (fnInfo.get('functionName'), paramIdx)
                relatedFuncs = CallingSpread[node]
                lvar['callingDepth'] = len(relatedFuncs)
            else:
                relatedFuncs = set()
                for calledFunc in lvar.get('usedAsArg'):
                    relatedFuncs.update(CallingSpread[calledFunc])
                lvar['callingDepth'] = len(relatedFuncs) + 1

def process(callInfo):
    for fnInfo in callInfo:
        processFnInfo(fnInfo)

    anaysisCallChian(callInfo)
    
def forgetDemangle(callInfo):
    for fnInfo in callInfo:
        try:
            demangledName = demangle(fnInfo['functionName'])
        except:
            demangledName = fnInfo['functionName']

        if len(demangledName) == 0:
            demangledName = fnInfo['functionName']
        else:
            demangledName = demangledName.split('(')[0]

        fnInfo['functionName'] = demangledName

def worker(jsonPath):
    assert os.path.exists(jsonPath), '%s Not Exits.' % jsonPath
    logger.info('[+] handing %s' % jsonPath)
    
    fp = open(jsonPath)
    callInfo = json.load(fp)
    fp.close()

    # demangle 
    forgetDemangle(callInfo)

    process(callInfo)

    saveTo = jsonPath.replace('.ea.exp2.json', '.ea.exp2.1.jsonl')
    with open(saveTo, 'w') as saveIO:
        for fnInfo in callInfo:
            obj = {
                key: fnInfo[key]
                for key in ('functionName', 'functionStart', 'lvariable')
            }
            obj['ELF'] = jsonPath.replace('.ea.exp2.json', '')
            saveIO.write(json.dumps(obj) + '\n')
            saveIO.flush()

def speedup(ELFCollect):
    numCores = 80
    pool = multiprocessing.Pool(processes=numCores)

    list(tqdm(pool.imap_unordered(worker, ELFCollect), total=len(ELFCollect)))
    pool.close()
    pool.join()


SAVT_TO  = 'result.jsonl'
# DATA_DIR = '/data/lgy/Projects/dataTypeInference/project/experiment/empiricalAnalysis/exp2/demo'
DATA_DIR = '/archive/lgy/TYDA/x86_64/O0'

def main():
    expResultList = getFilesBySuffix(DATA_DIR, '.ea.exp2.json')
    logger.info('[+] Found *.ea.lab2.json %d' % (len(expResultList)))
    expResultList = sorted(
        expResultList,
        key=lambda x: os.path.getsize(x)
    )

    # for expResult in expResultList[24679:]:
    # worker(expResult)
    speedup(expResultList[24679:])
        # try:
        #     worker(expResult)
        # except:
        #     pass

if __name__ == '__main__':
    main()