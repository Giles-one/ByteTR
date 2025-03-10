import os
import re
import json
from collections import defaultdict

counter = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))


def step1():
    with open('result.jsonl') as fp:
        for line in fp:
            Ref = json.loads(line)
            memberInfo = Ref['memberInfo']
            objectInfo = Ref['objectInfo']
            counter[memberInfo['memberOffset']][memberInfo['memberSize']][objectInfo['objectType']] += 1
            # break
    # normal_dict = {k: dict(v) for k, v in counter.items()}
    with open('final.json', 'w') as fp:
        json.dump(counter, fp, indent=2)

def step2():
    with open('final.json') as fp:
        data = json.load(fp)
    
    tmp = []
    for k1, v1 in data.items():
        for k2, v2 in v1.items():
            uniqueType = len(v2)
            Hit = sum(list(v2.values()))
            
            tmp.append((
                int(k1),
                int(k2),
                Hit,
                uniqueType, 
                '%.1f%%' % ((Hit-uniqueType) * 100 /Hit)
            ))

    tmp = sorted(tmp, key=lambda x: (-x[2], x[0], x[1]))
    # tmp = sorted(tmp, key=lambda x: (-(x[2] - x[3])/x[2]))
    for a in tmp:
        print('%3d & %3d & %10d & %10d & %s' % (a[0], a[1], a[2], a[3], a[4]))
if __name__ == '__main__':
    step2()