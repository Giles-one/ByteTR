import os
import sys
import json
import torch
import wandb
import argparse

import logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)

from model import GGNN
from datetime import datetime
from torch_geometric.loader import DataLoader
from dataset import MyGraphDataset

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info('Current using device: %s' % device)


def train(model, loader, optimizer, criterion):
    model.train()
    total_loss = 0
    for data in loader:
        data = data.to(device)
        optimizer.zero_grad()
        out = model(data.x, data.edge_index, data.edge_attr, data.batch)
        loss = criterion(out, data.y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * data.num_graphs
    return total_loss / len(loader.dataset)


def evaluate(model, loader):
    model.eval()
    correct = 0
    total = 0
    class_correct = {}
    class_total = {}

    for data in loader:
        data = data.to(device)
        with torch.no_grad():
            out = model(data.x, data.edge_index, data.edge_attr, data.batch)
        pred = out.argmax(dim=1)

        correct += int((pred == data.y).sum())
        total += data.y.size(0)

        for i in range(len(data.y)):
            label = data.y[i].item()
            if label not in class_correct:
                class_correct[label] = 0
                class_total[label] = 0

            class_total[label] += 1
            if pred[i] == label:
                class_correct[label] += 1

    class_accuracy = {label: class_correct[label] / class_total[label] if class_total[label] > 0 else 0
                      for label in class_total}
    overall_accuracy = correct / total if total > 0 else 0

    return overall_accuracy, class_accuracy


def parse_args():
    parser = argparse.ArgumentParser(description="Parse command line arguments.")
    parser.add_argument('--arch', type=str, required=True, choices=['x86_64', 'x86_32', 'aarch64', 'mips'], help='Specify the architecture (x86_64, x86_32, aarch64, mips).')
    parser.add_argument('--opt', type=str, required=True, choices=['O0', 'O1', 'O2', 'O3'], help='Specify the Optimization (O0, O1, O2, O3).')
    parser.add_argument('--lr', type=float, default=0.001, help='Learning rate')
    parser.add_argument('--nepoch', type=int, default=200, help='Number of epochs')
    parser.add_argument('--batch_size', type=int, default=32, help='Batch size')
    parser.add_argument('--feature_dim', type=int, default=64, help='Feature dimension')
    parser.add_argument('--gate_agg', type=str, choices=['add', 'mean', 'max'], default='add', help='Gate aggregation method')
    parser.add_argument('--global_agg', type=str, choices=['add', 'mean', 'max'], default='max', help='Global aggregation method')
    parser.add_argument('--layer_GRU', type=int, default=3, help='Number of GRU layers')
    parser.add_argument('--layer_GNN', type=int, default=4, help='Number of GNN layers')
    parser.add_argument('--checkpoint_dir', type=str, default='./checkpoints', help='Directory to save checkpoints')
    return parser.parse_args()

ROOT = 'dataset/'
def main(args):
    datasetPath = os.path.join(ROOT, args.arch, args.opt)
    assert os.path.exists(datasetPath)
    config = {
        'dataset': '%s/config.json' % datasetPath,
        'node': {
            'id2word': '%s/%s/vcabs_id2word.json' % (datasetPath, 'summary'),
            'word2id': '%s/%s/vcabs_word2id.json' % (datasetPath, 'summary')
        },
        'edge': {
            'id2word': '%s/%s/edge_vcabs_id2word.json' % (datasetPath, 'summary'),
            'word2id': '%s/%s/edge_vcabs_word2id.json' % (datasetPath, 'summary')
        },
        'model': {
            'arch':        args.arch,
            'opt':         args.opt,
            'lr':          args.lr,             # 0.005, 0.001, 0.0005, 0.0001
            'nepoch':      args.nepoch,         # 200
            'batch_size':  args.batch_size,     # 32, 64
            'feature_dim': args.feature_dim,    # 64, 128
            'gate_agg':    args.gate_agg,       # add, mean, max
            'global_agg':  args.global_agg,     # add, mean, max
            'layer_GRU':   args.layer_GRU,      # 3, 4, 5
            'layer_GNN':   args.layer_GNN,      # 3, 4, 5
            'save_dir':    args.checkpoint_dir  # checkpoints
        }
    }


    model_config = config['model']
    wandb.init(
        project='ByteTR',
        name=datetime.now().strftime("%Y-%m-%d-%H-%M-%S"),
        config=model_config
    )

    mydataset = MyGraphDataset(config, shuffle=True, threshold=6000)
    
    mydatasetLength = len(mydataset)
    valDatasetLength = int(mydatasetLength * 0.2)
    testDatasetLength = int(mydatasetLength * 0.2)
    trainDatasetLength = mydatasetLength - valDatasetLength - testDatasetLength

    trainDataset = mydataset[:trainDatasetLength]
    valDataset   = mydataset[trainDatasetLength: trainDatasetLength + valDatasetLength]
    testDataset  = mydataset[trainDatasetLength + valDatasetLength:]

    batch_size = model_config['batch_size']
    train_loader = DataLoader(
        trainDataset,
        batch_size=batch_size,
        shuffle=True
    )
    val_loader = DataLoader(
        valDataset,
        batch_size=batch_size,
        shuffle=False
    )
    test_loader = DataLoader(
        testDataset,
        batch_size=batch_size,
        shuffle=False
    )

    model = GGNN(
        n_node_feat_dim=model_config['feature_dim'],
        n_node_label=mydataset.n_node_label,
        n_edge_label=mydataset.n_edge_label,
        n_output_label=mydataset.n_label,
        num_gate_graph_conv=model_config['layer_GNN'],
        num_one_gate_graph_conv_layer=model_config['layer_GRU'],
        gate_graph_conv_aggr=model_config['gate_agg'],
        global_aggr=model_config['global_agg']
    )
    model = model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=model_config['lr'])
    criterion = torch.nn.CrossEntropyLoss()
    
    save_dir = os.path.join(model_config['save_dir'], model_config['arch'], model_config['opt'])
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    config_path = os.path.join(save_dir, 'config.json')
    with open(config_path, 'w') as fp:
        json.dump(config, fp, indent=2)

    result = {}
    nepoch = model_config['nepoch']
    for epoch in range(nepoch):
        logger.info('epoch %d' % epoch)
        loss = train(model, train_loader, optimizer, criterion)
        train_acc, train_class_acc = evaluate(model, train_loader)
        val_acc, val_class_acc = evaluate(model, val_loader)
        
        wandb.log(
            {
                'loss': loss,
                'train_acc': train_acc,
                'val_acc': val_acc
            }, 
            step=epoch
        )
        
        logger.info(f'Epoch: {epoch:03d}, Loss: {loss:.4f}, Train Acc: {train_acc:.4f}, Val Acc: {val_acc:.4f}')
        sys.stdout.flush()
		
        result[epoch] = {
            'train': train_class_acc,
            'val': val_class_acc
        }
        save_path = os.path.join(save_dir, f'model_epoch_{epoch}.pth')
        torch.save(model.state_dict(), save_path)

        result_path = os.path.join(save_dir, 'result.json')
        with open(result_path, 'w') as fp:
            json.dump(result, fp, indent=2)


if __name__ == '__main__':
    args = parse_args()
    main(args)

'''
CUDA_VISIBLE_DEVICES=3 python train.py \
    --arch x86_64 \
    --opt O0 \
    --lr 0.0001 \
    --nepoch 200 \
    --batch_size 32 \
    --feature_dim 128 \
    --gate_agg add \
    --global_agg max \
    --layer_GRU 3 \
    --layer_GNN 3 \
    --checkpoint_dir checkpoints
'''
