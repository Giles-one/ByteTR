import os
import json
import subprocess
import multiprocessing as mp

from typing import List

import logging
logging.basicConfig(
    level = logging.INFO,
    format='[%(process)d]->[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)

PAYLOAD = 'payload.py'
if not os.path.exists(PAYLOAD):
    logger.error('WTF? Can not find {}'.format(PAYLOAD))
    exit(-1)
PAYLOAD = os.path.abspath(PAYLOAD)
logger.info('Load payload {}'.format(PAYLOAD))


def cleanDist(ELFPath):
    SUFFIX = ('.id0', '.id1', '.id2', '.nam', '.til')
    for suf in SUFFIX:
        distPath = ELFPath + suf
        if not os.path.exists(distPath):
            continue
        os.remove(distPath)

def processTask(ELFPath: str):
    logFile = ELFPath + '.ida.log'
    cmd = f'idat64 -A -L{logFile} -S{PAYLOAD} {ELFPath}'
    logger.info(cmd)
    
    saveTo = ELFPath + '.ea.exp2.json'
    if os.path.exists(saveTo):
        return
    
    cleanDist(ELFPath)
    subprocess.run(
        cmd,
        shell=True,
        check=True,
        timeout=20 * 60,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if not os.path.exists(saveTo):
        raise Exception('IDA Process Error')

def workerProcess(undoELF: mp.Queue, failELF: mp.Queue, processId: int):
   while True:
        if undoELF.empty():
            break
        ELFPath = undoELF.get()
        undoNum = undoELF.qsize()
        logger.info('[{}][{}][{}]'.format(processId, undoNum, ELFPath))
        try:
            processTask(ELFPath)
        except:
            logger.error('Fails {}'.format(ELFPath))
            failELF.put(ELFPath)

def main():
    with open("ELF.json") as fp:
        ELFPathLists = json.load(fp)
    ELFPathLists = [
        ELFPath.replace('/archive/lgy/TYDA/x86_64/O0/', '/dataset/')
        for ELFPath in ELFPathLists
    ]
    # breakpoint()
    ELFPathLists = [ELFPath for ELFPath in ELFPathLists if os.path.exists(ELFPath)]
    logger.info('Get {} ELF files.'.format(len(ELFPathLists)))
    # ELFPathLists = ELFPathLists[:1]

    undoELF = mp.Queue()
    failELF = mp.Queue()
    for ELFPath in ELFPathLists:
        undoELF.put(ELFPath)
    
    numProcess = 80
    processes = []
    for processId in range(numProcess):
        p = mp.Process(target=workerProcess, args=(undoELF, failELF, processId))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()
    
    ELFFailList = []
    while not failELF.empty():
        ELFFailList.append(failELF.get())
    
    logger.error('fails {} times'.format(len(ELFFailList)))
    with open('fails.log', 'w') as fail:
        json.dump(ELFFailList, fail, indent='\t')

if __name__ == '__main__':
    main()
