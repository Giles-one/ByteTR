import os
import tqdm
import json
import argparse
from collections import defaultdict

from dataset import labels, id2label, label2id

infoTosave = []
word_freq = defaultdict(int)
edge_freq = defaultdict(int)
type_sum  = defaultdict(int)

def processElfInfo(elfPath, save_dataset_config, tmp_file_handler):
    try:
        with open(elfPath) as fp:
            elfInfo = json.load(fp)
    except json.JSONDecodeError as e:
        print('[!] Failed to load json file. %s' % elfPath)
        return

    functions = elfInfo['function']
    for fnInfo in functions:
        variable = fnInfo['variable']
        variable.extend(fnInfo['parameter'])
        for varInfo in variable:
            if 'graph' not in varInfo.keys():
                continue
            if len(varInfo['graph']['node']) == 0:
                continue
            if len(varInfo['graph']['node']) > 2000:
                continue
            for node in varInfo['graph']['node']:
                if node['text'].startswith('op@call_func_arg'):
                    node['text'] = node['text'][:17]
                word_freq[node['text']] += 1
            
            if "type" not in varInfo.keys():
                continue
            if not varInfo['type']:
                continue
            if varInfo['type'] not in label2id.keys():
                continue
            
            type_sum[varInfo['type']] += 1

            type_id = label2id[varInfo['type']]
            type_dump_file_handler = tmp_file_handler[type_id]

            oneline = {
                'label': type_id,
                'type' : varInfo['type'],
                'graph': varInfo['graph']
            }
            type_dump_file_handler
            json.dump(oneline, type_dump_file_handler)
            type_dump_file_handler.write('\n')
            type_dump_file_handler.flush()
            save_dataset_config['typesum'][type_id] += 1

            for link in  varInfo['graph']['edge']:
                edge_freq[link['attr'].lower()] += 1

configPath = "../BinaryProcessing/config/binary.config.json"
publicConfigPath = "../BinaryProcessing/config/public.config.json"

def findFilesWithExt(root, ext):
    fileList = []
    for root, dirs, files in os.walk(root):
        for file in files:
            if not file.endswith(ext):
                continue
            filePath = os.path.join(root, file)
            fileList.append(filePath)
    return fileList

def main(args):
    assert os.path.exists(configPath), 'Config file does not exists. %s' % configPath
    with open(configPath) as fp:
        config = json.load(fp)

    global arch, opt
    arch = args.arch
    assert arch in config['arch']
    opt  = args.opt
    assert  opt in config['opt']
    
    rawBinaryPath = os.path.join(config['TYDA'], arch, opt)
    assert os.path.exists(rawBinaryPath), 'Arch raw binary not exists. %s' % rawBinaryPath

    global publicConfig
    assert os.path.exists(publicConfigPath), "public config not exists. %s" % publicConfigPath
    with open(publicConfigPath) as fp:
        publicConfig = json.load(fp)

    savedInfoSuffix = publicConfig['suffix']['savedInfoSuffix']
    fileList = findFilesWithExt(rawBinaryPath, savedInfoSuffix)    
    collect = sorted(
        fileList,
        key=lambda x: os.path.getsize(x)
    )
    collect = collect[:6000]
    print('[+] Collect %s %d' % (savedInfoSuffix, len(collect)))

    dstDIR = os.path.join('dataset', arch, opt)
    labelPath = os.path.join(dstDIR, 'label')
    if not os.path.exists(labelPath):
        os.makedirs(labelPath)
    
    save_dataset_config = {
        'typesum': { key: 0 for key, value in id2label.items()},
        'id2path': { key: "%s/label/%s.jsonl" % (dstDIR, value) for key, value in id2label.items()}
    }
    tmp_file_handler = { 
        key: open(save_dataset_config['id2path'][key], 'w')
        for key, _ in id2label.items()
    }

    for elfPath in tqdm.tqdm(collect):
        processElfInfo(elfPath, save_dataset_config, tmp_file_handler)

    print('[+] Closing file handler ...')
    for _, filehandler in tmp_file_handler.items():
         filehandler.close()
    print("[+] Done")

    dataset_config_path = os.path.join(dstDIR, 'config.json')    
    with open(dataset_config_path, "w") as fp:
        json.dump(save_dataset_config , fp, indent=2)
        
    sorted_dict = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
    id2word = {}
    word2id = {}
    for idx, word in enumerate(sorted_dict):
        id2word[idx] = word[0]
        word2id[word[0]] = idx

    edge_sorted_dict = sorted(edge_freq.items(), key=lambda x: x[1], reverse=True)
    edge_id2word = {}
    edge_word2id = {}
    for idx, word in enumerate(edge_sorted_dict):
        edge_id2word[idx] = word[0]
        edge_word2id[word[0]] = idx

    summaryPath = os.path.join(dstDIR, 'summary')
    if not os.path.exists(summaryPath):
        os.makedirs(summaryPath)

    print('[+] Saving sum.json ...')
    with open(os.path.join(summaryPath, 'dataset.sum.json'), 'w') as fp:
        json.dump(type_sum, fp, indent=2)
    
    with open(os.path.join(summaryPath, 'edge.sum.json'), 'w') as fp:
        json.dump(edge_freq, fp, indent=2)

    print('[+] Saving vcabs.json ...')
    with open(os.path.join(summaryPath, 'vcabs_id2word.json'), 'w') as fp:
        json.dump(id2word, fp, indent=2)
    
    with open(os.path.join(summaryPath, 'vcabs_word2id.json'), 'w') as fp:
        json.dump(word2id, fp, indent=2)
    
    with open(os.path.join(summaryPath, 'edge_vcabs_id2word.json'), 'w') as fp:
        json.dump(edge_id2word, fp, indent=2)
    
    with open(os.path.join(summaryPath, 'edge_vcabs_word2id.json'), 'w') as fp:
        json.dump(edge_word2id, fp, indent=2)

def argParse():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--arch', 
        type=str, 
        required=True, 
        help="Architecture type"
    )
    parser.add_argument(
        '--opt', 
        type=str, 
        required=True, 
        help="Optimization Method"
    )
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = argParse()
    main(args)

'''
python preprocess.py \
    --arch x86_64 \
    --opt O0
'''