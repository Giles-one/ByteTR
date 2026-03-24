import json
import ijson
import torch
import random
from tqdm import tqdm

from torch_geometric.data import Data, Dataset
from torch_geometric.loader import DataLoader

labels = [
    'i8',
    'u8',
    'i16',
    'u16',
    'i32',
    'u32',
    'i64',
    'u64',
    'float',
    'double',
    'struct',
    'array',

    'i8*',
    'u8*',
    'i16*',
    'u16*',
    'i32*',
    'u32*',
    'i64*',
    'u64*',
    'float*',
    'double*',
    'struct*',
    'void*',
]

id2label = {index: element for index, element in enumerate(labels)}
label2id = {element: index for index, element in enumerate(labels)}

class MyGraphDataset(Dataset):
    def __init__(self, dataset_config, shuffle=False, **kwargs):
        super().__init__(root=None, transform=None, pre_transform=None)
        assert isinstance(dataset_config, dict)
    
        self._dataset_path = dataset_config['dataset']

        if kwargs.get('threshold'):
            self.threshold = kwargs.get('threshold')
        else:
            self.threshold = 1000

        node_id2word_path = dataset_config['node']['id2word']
        with open(node_id2word_path) as fp:
            self._node_id2word = json.load(fp)
        node_word2id_path = dataset_config['node']['word2id']
        with open(node_word2id_path) as fp:
            self._node_word2id = json.load(fp)

        edge_id2word_path = dataset_config['edge']['id2word']
        with open(edge_id2word_path) as fp:
            self._edge_id2word = json.load(fp)
        edge_word2id_path = dataset_config['edge']['word2id']
        with open(edge_word2id_path) as fp:
            self._edge_word2id = json.load(fp)

        self.data_list = []
        self._load_dataset()

        if shuffle:
            print("Shuffle ...")
            random.shuffle(self.data_list)
            print("Shuffle Ok")

    def _load_dataset(self):
        print('Loading ...')
        datasetJson = []
        with open(self._dataset_path) as fp:
            dataset_config = json.load(fp)
        
        for key, value in dataset_config['id2path'].items():
            print('label %s ...' % key)
            with open(value) as fp:
                for i, line in enumerate(fp):
                    if i >= self.threshold:
                        break
                    datasetJson.append(json.loads(line))
        print('Load Ok ...')
        # breakpoint()

        print('Tokenize ...')
        for item in tqdm(datasetJson):
            graph = item['graph']

            node = graph['node']
            if not all(a['id'] == idx for idx, a in enumerate(node)):
                continue
            node_labels = [self._node_word2id[one['text']] for one in node]

            edge = graph['edge']
            edge_labels = []
            edge_index = []
            for e in edge:
                if e['link'][0] >= len(node_labels):
                    breakpoint()
                if e['link'][1] >= len(node_labels):
                    # breakpoint()
                    continue
                
                edge_index.append(e['link'])
                edge_labels.append(self._edge_word2id[e['attr'].lower()])

            y = item['label']

            node_label_tensor = torch.tensor(node_labels, dtype=torch.long).view(-1)
            edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
            edge_attr_tensor = torch.tensor(edge_labels, dtype=torch.long).view(-1)
            y_tensor = torch.tensor(y, dtype=torch.long)

            data = Data(x=node_label_tensor, edge_index=edge_index_tensor, edge_attr=edge_attr_tensor, y=y_tensor)
            self.data_list.append(data)

        print('Ok')

    @property
    def n_node_label(self):
        return len(self._node_word2id)

    @property
    def n_edge_label(self):
        return len(self._edge_word2id)

    @property
    def n_label(self):
        return len(labels)

    def len(self):
        return len(self.data_list)

    def get(self, idx):
        return self.data_list[idx]

if __name__ == '__main__':
    config = {
        'dataset': 'dataset/config.json',
        'node': {
            'id2word': 'vcabs_id2word.json',
            'word2id': 'vcabs_word2id.json'
        },
        'edge': {
            'id2word': 'edge_vcabs_id2word.json',
            'word2id': 'edge_vcabs_word2id.json'
        }
    }

    a = MyGraphDataset(config, shuffle=True, threshold=2000)
    train_dataset = a[:32 * 5]
    train_loader = DataLoader(a, batch_size=32)
    for batch in train_loader:
        print(batch)
        break
