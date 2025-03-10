import glob
import json

from collections import defaultdict

Map = defaultdict(lambda: defaultdict(int))

def main():
    OPTI = ('O0', 'O1', 'O2', 'O3')
    expResult = {
        opti: glob.glob(f'result.{opti}.*')[0]
        for opti in OPTI
    }

    for key, value in expResult.items():
        with open(value) as fp:
            for line in fp:
                obj = json.loads(line)
                tloca = obj.get('tloca')
                Map[key][tloca] += 1
                
    with open('out.json', 'w') as fp:
        json.dump(Map, fp, indent=2)

if __name__ == '__main__':
    main()
