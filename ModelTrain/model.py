import torch

from torch import nn
from torch_geometric.nn import GatedGraphConv
from torch_geometric.nn import global_mean_pool, global_max_pool, global_add_pool

class EmbeddingEncoder(torch.nn.Module):
    def __init__(self, n_node_feat_dim,  n_node_attr):
        super().__init__()
        self.node_encoder = nn.Embedding(n_node_attr, n_node_feat_dim)
        self._n_node_attr = n_node_attr

    def forward(self, x):
        x = self.node_encoder(x)
        return x

class GGNN(torch.nn.Module):
    def __init__(self,
                 n_node_feat_dim,
                 n_node_label,
                 n_edge_label,
                 n_output_label,
                 num_gate_graph_conv=4,
                 num_one_gate_graph_conv_layer=3,
                 gate_graph_conv_aggr='add',
                 global_aggr='max'
    ):
        super(GGNN, self).__init__()
        self.encoder = EmbeddingEncoder(
            n_node_feat_dim = n_node_feat_dim,
            n_node_attr = n_node_label,
        )

        self.convs = torch.nn.ModuleList()
        for _ in range(num_gate_graph_conv):
            conv = GatedGraphConv(
                out_channels=n_node_feat_dim,
                num_layers=num_one_gate_graph_conv_layer,
                aggr=gate_graph_conv_aggr
            )
            self.convs.append(conv)

        if global_aggr == 'max':
            self.aggr = global_max_pool
        elif global_aggr == 'mean':
            self.aggr = global_mean_pool
        elif global_aggr == 'add':
            self.aggr = global_add_pool
        else:
            raise ValueError(f"Unsupported global aggregation method: {global_aggr}")

        self.decoder = nn.Sequential(
            torch.nn.Linear(n_node_feat_dim, n_node_feat_dim),
            torch.nn.ReLU(),
            torch.nn.Dropout(p=0.5),
            torch.nn.Linear(n_node_feat_dim, n_output_label)
        )

    def forward(self, x, edge_index, edge_feat, batch, return_embed=False):
        e = edge_feat
        x = self.encoder(x)

        for conv in self.convs:
            x = conv(x, edge_index, e)

        x = self.aggr(x, batch)
        if not return_embed:
            x = self.decoder(x)
            return x
        else:
            embeddings = x.detach().clone()
            x = self.decoder(x)
            return x, embeddings

