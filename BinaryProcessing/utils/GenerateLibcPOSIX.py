import json
from collections import defaultdict

token_counts = defaultdict(int)

def parseFnSig(line):
    line = line.replace('*', ' * ')
    line = line.replace('(', ' ( ')
    line = line.replace(')', ' ) ')
    # line = line.replace(']', '] ')
    # line = line.replace('[', ' [')
    line = line.replace(',', ' , ')
    line = line.replace('  ', ' ')

    first = line.find('(')
    tmp = line[:first].strip()
    tmpId = tmp.rfind(' ')
    ret = tmp[: tmpId].strip()
    fname = tmp[tmpId: ].strip()

    last  = line.rfind(')')
    tmp = line[first+1: last].strip()
    tmp = tmp.split(',')
    tmp = [t.strip() for t in tmp]
    para = []
    for t in tmp:
        rid = t.rfind(' ')
        if rid == -1:
            para.append(t)
        else:
            para.append(t[:rid])
    para = [t.strip() for t in para]

    # if ret.endswith('*'):
    #     ret = 'struct *'
    # else:
    #     ret = 'struct'
    # token_counts[ret] += 1
    # for p in para:
    #     p = p.replace('const', '')
    #     p = p.strip()
    #     if p.startswith('struct'):
    #         if p.endswith('*'):
    #             p = 'struct *'
    #         else:
    #             p = 'struct'
    #     token_counts[p] += 1

    return ret, fname, para

def main():
    fp = open('./libc_functions')
    content = fp.read()
    fp.close()
    content = content.strip()
    functions = content.split('\n')
    collect = {}
    for line in functions:
        print(line)
        ret, fname, param = parseFnSig(line)
        collect[fname] = (ret, param)

    with open('POSIX.json', 'w') as fp:
        json.dump(collect, fp, indent=2)

if __name__ == '__main__':
    main()