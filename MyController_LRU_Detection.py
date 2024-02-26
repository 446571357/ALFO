# 实现以ip端口粒度下发流表项
# 流表项替换机制FIFO（存活时间最长）
# 每秒向交换机请求端口信息和流表项信息
# 每秒保存交换机特征至csv
# 每秒保存流表项特征至csv

import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, in_proto, ipv4, udp, tcp, vlan
import csv
import os

############ Detection ######################## Detection ######################## Detection ######################## Detection ############
import torch
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data
import numpy as np

class AttentionModule(torch.nn.Module):
    
    def __init__(self, args):
        """
        :param args: Arguments object.
        """
        super(AttentionModule, self).__init__()
        self.args = args
        self.setup_weights()  # 定义权重矩阵
        self.init_parameters()  # 初始化权重

    # 定义权重矩阵 [f3,f3]
    def setup_weights(self):
        """
        Defining weights.
        """
        self.weight_matrix = torch.nn.Parameter(torch.Tensor(self.args["filters_3"],
                                                             self.args["filters_3"]))

    # 初始化权重
    def init_parameters(self):
        """
        Initializing weights.
        """
        torch.nn.init.xavier_uniform_(self.weight_matrix)

    # 生成图级向量 [f3,1]
    def forward(self, embedding):
         sigmoid_scores = torch.sigmoid(torch.mm(embedding, transformed_global.view(-1, 1)))
        representation = torch.mm(torch.t(embedding), sigmoid_scores)
        return torch.t(representation)

class Classifier(torch.nn.Module):
    def __init__(self, opt):
        super(Classifier, self).__init__()
        # self.args = get_config('./Config/classifier_config.yaml')
        self.args = {
            'number_of_labels': 8,  # 节点特征维度大小
            'n_classes': 2,  # 分类数量
        }

        self.setup_layers()
        self.opt = opt

    # 神经网络组成
    def setup_layers(self):
        """
        Creating the layers.
        """
        self.convolution_1 = GCNConv(self.args["number_of_labels"], self.args["filters_1"])

        self.attention = AttentionModule(self.args)
        self.graph_classify = torch.nn.Linear(self.args["filters_3"], self.args["n_classes"]) 

        self.fully_connected_first = torch.nn.Linear(self.args["filters_3"], self.args["bottle_neck_neurons"])
        self.node_classify = torch.nn.Linear(self.args["bottle_neck_neurons"], 2) 

       def convolutional_pass(self, edge_index, features):
        features = self.convolution_1(features, edge_index)
        features = torch.nn.functional.relu(features)
        features = torch.nn.functional.dropout(features,
                                               p=self.args["dropout"],
                                               training=self.training)
        return features

    # 返回图类别
    # 输入：data(节点特征矩阵[N,number_of_labels]，邻接矩阵 [2,E])
    def forward(self, data):
        edge_index = data.edge_index   # 邻接矩阵 [2,E]
        features = data.x  # 节点特征矩阵 [N,number_of_labels]
        features = self.convolutional_pass(edge_index, features) 
        if self.opt == 'node':
            features = torch.nn.functional.relu(self.fully_connected_first(features))
            features = torch.sigmoid(self.node_classify(features))
        return features

class init_Model():
    def __init__(self, load_path, operation):
        super(init_Model, self).__init__()
        self.load_path = load_path
        self.operation = operation

        self.model = Classifier(self.operation)     # 初始化模型架构
        self.model.load_state_dict(torch.load(self.load_path))  # 加载模型
        # print(self.load_path)
        # print('load_model:', self.model)

       def data_handle(self, features):
        x = []
        for feature in features.values():
            duration = int(feature['duration'])
            bytes = int(feature['bytes'])
            packets = int(feature['packets']) 
            if packets:
                average_bytes = bytes / packets
                average_time_interval = duration / packets
            else:
                average_bytes = 0
                average_time_interval = duration
            if duration:
                rate = bytes / duration  # 流表项传输速率
            else:
                rate = bytes
            bytes_cv = self.coefficient_variation(feature['B_list'])
            interval_cv = self.coefficient_variation(feature['T_list'])
            node_features = [duration, bytes, packets, average_bytes, rate, average_time_interval, bytes_cv, interval_cv]
            x.append(node_features)

        edge_index = []
        for src in ip_dict:
            for index, i in enumerate(ip_dict[src]):
                for j in ip_dict[src][index + 1:]:
                    if j == i:
                        continue
                    edge_index.append([i, j])

        y_node = []
        y_graph = [0]
        for feature in features.values():
            if int(feature['is_attack']) == 1:
                # print(feature)
                y_graph = [1]
            y_node.append(int(feature['is_attack']))

        x = torch.tensor(np.array(self.normalization(x)), dtype=torch.float)
        edge_index = torch.tensor(np.array(edge_index), dtype=torch.long)
        y_graph = torch.tensor(np.array(y_graph), dtype=torch.long)
        y_node = torch.tensor(np.array(y_node), dtype=torch.long)
        data = Data(x=x, edge_index=edge_index.t().contiguous(), y_graph=y_graph, y_node=y_node)
        return data

    def get_prediction(self, features):
        self.model.eval()
        data = self.data_handle(features)
        prediction = self.model(data)
        prediction = prediction.argmax(dim=1)
        return prediction


############ Detection ######################## Detection ######################## Detection ######################## Detection ############

def replace_match(flow_feature):
    match = [flow for flow in flow_feature.values() if flow['priority'] == 1][0]['match']
    return match


# 为不同的数据包定义match域
# 返回待添加流表项的match
def add_match(parser, in_port, pkt):
    eth = pkt.get_protocol(ethernet.ethernet)
    src, dst = eth.src, eth.dst  # 源MAC，目的MAC
    if eth.ethertype == ether_types.ETH_TYPE_8021Q:
        eth = pkt.get_protocol(vlan.vlan)
        # print(eth)
    eth_type = eth.ethertype  # 数据包类型
    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    if eth_type == ether_types.ETH_TYPE_ARP:  # ARP协议
        # print("ARP:", src, dst)
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_ARP, eth_src=src, eth_dst=dst)
    elif eth_type == ether_types.ETH_TYPE_IP:  # IP数据包
        _ip = pkt.get_protocol(ipv4.ipv4)
        proto, ip_src, ip_dst = _ip.proto, _ip.src, _ip.dst
        if proto == in_proto.IPPROTO_IP or proto == in_proto.IPPROTO_ICMP:
            # print("IP/ICMP:", ip_src, ip_dst)
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip_src,
                                    ipv4_dst=ip_dst)
        else:
            if proto == in_proto.IPPROTO_UDP:
                _udp = pkt.get_protocol(udp.udp)
                # print("UDP:", ip_src, _udp.src_port, ip_dst, _udp.dst_port)
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_src,
                                        ipv4_dst=ip_dst,
                                        ip_proto=proto,
                                        udp_src=_udp.src_port,
                                        udp_dst=_udp.dst_port)
            elif proto == in_proto.IPPROTO_TCP:
                _tcp = pkt.get_protocol(tcp.tcp)
                # if ip_src.startswith('250.'):
                #     print("TCP:", ip_src, _tcp.src_port, ip_dst, _tcp.dst_port)
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_src,
                                        ipv4_dst=ip_dst,
                                        ip_proto=proto,
                                        tcp_src=_tcp.src_port,
                                        tcp_dst=_tcp.dst_port)
    return match


# 追加内容至csv
def add_to_csv(data, filename):
    with open(filename, 'a+', newline='') as f:  # newline='': 这个限定插入新数据不会空行，如果没有这个，每次插入数据都会隔行填数据
        csv_write = csv.writer(f)
        csv_write.writerow(data)

# 初始化交换机特征字典
def init_switch_feature(dpid):
    switch_feature = {
        'dpid': dpid,
        'is_attack': 0,  # 异常状态
        'flow_number': 0,  # 流表项数量
        'attack_number': 0,  # 恶意流数量
        'del_normal': 0,  # 删除正常流数量
        'del_attack': 0,  # 删除的恶意流数量
        'port': [],  # 端口号
        'ReceivePackets': {},  # 各端口接收的数据包数 {'port':number}
        'ReceiveBytes': {},  # 各端口接收的字节数
        'SendPackets': {},  # 各端口发送的数据包数
        'SendBytes': {}  # 各端口发送的字节数
    }
    return switch_feature
# 更新端口信息
def update_port_statistic(switch_feature, body):
    for data in body:
        # print(switch_feature['port'])
        if data.port_no not in switch_feature['port']:
            switch_feature['port'].append(data.port_no)
        switch_feature['ReceivePackets'][data.port_no] = data.rx_packets
        switch_feature['ReceiveBytes'][data.port_no] = data.rx_bytes
        switch_feature['SendPackets'][data.port_no] = data.tx_packets
        switch_feature['SendBytes'][data.port_no] = data.tx_bytes
# 异常状态、流表项数量（总数量、恶意流数量）、删除流数量（恶意流、正常流）
def save_flow_number(switch_feature, time, dpath):
    file = dpath + '/FlowNumber.csv'
    data = []
    data.append(time)
    data.append(switch_feature['is_attack'])
    data.append(switch_feature['flow_number'])
    data.append(switch_feature['attack_number'])
    data.append(switch_feature['del_normal'])
    data.append(switch_feature['del_attack'])
    add_to_csv(data, file)
# 各端口的接收和发送的数据包数、字节数
def save_port_data(switch_feature, key, time, dpath):
    file = dpath + '/' + key + '.csv'
    data = []
    data.append(time)
    for i in switch_feature['port']:
        data.append(switch_feature[key][i])
    add_to_csv(data, file)
# 保存交换机特征
def save_switch_feature(switch_feature, flow_feature, dpath, time):
    # 更新流表数量信息
    switch_feature['flow_number'] = len(flow_feature)
    # print("save_switch_feature", switch_feature['flow_number'], len(flow_feature))
    attack_number = 0
    for flow in flow_feature.values():
        # print("save_switch_feature", flow.match)
        if flow['ip_src'] and flow['ip_src'].startswith('250.'):
            attack_number += 1
    switch_feature['attack_number'] = attack_number
    # 保存数据至文件
    os.makedirs(dpath, exist_ok=True)  # 确保文件目录存在
    save_flow_number(switch_feature, time, dpath)
    save_port_data(switch_feature, 'ReceivePackets', time, dpath)
    save_port_data(switch_feature, 'ReceiveBytes', time, dpath)
    save_port_data(switch_feature, 'SendPackets', time, dpath)
    save_port_data(switch_feature, 'SendBytes', time, dpath)


# 初始化流表项特征字典
# 每条流表项都对应该字典
def init_flow_feature(flow):
    is_attack = 0   # 是否为攻击流流表项
    # 源IP
    if 'ipv4_src' in flow.match:
        ip_src = flow.match['ipv4_src']
        if flow.match['ipv4_src'].startswith('250.'):  # 攻击流流表项
            is_attack = 1
    elif 'eth_src' in flow.match:
        ip_src = flow.match['eth_src']
    else:
        # print(flow.match)
        ip_src = None
    # 目的IP
    if 'ipv4_dst' in flow.match:
        ip_dst = flow.match['ipv4_dst']
    elif 'eth_dst' in flow.match:
        ip_dst = flow.match['eth_dst']
    else:
        # print(flow.match)
        ip_dst = None
    # 源port
    if 'udp_src' in flow.match:
        port_src = flow.match['udp_src']
    elif 'tcp_src' in flow.match:
        port_src = flow.match['tcp_src']
    else:
        # print(flow.match)
        port_src = None
    # 目的port
    if 'udp_dst' in flow.match:
        port_dst = flow.match['udp_dst']
    elif 'tcp_dst' in flow.match:
        port_dst = flow.match['tcp_dst']
    else:
        # print(flow.match)
        port_dst = None
    # 入端口
    if 'in_port' in flow.match:
        in_port = flow.match['in_port']
    else:
        # print(flow.match)
        in_port = None
    # ['ip_src', 'ip_dst', 'port_src', 'port_dst', 'in_port', 'out_port', 'duration', 'bytes', 'packets', 'active', 'match', 'priority', 'is_attack']
    flow_feature = {
        'ip_src': ip_src,  # 源ip
        'ip_dst': ip_dst,  # 目的ip
        'port_src': port_src,  # 源port
        'port_dst': port_dst,  # 目的port
        'in_port': in_port,  # 入端口
        'out_port': flow.instructions[0].actions[0].port,  # 出端口
        'duration': flow.duration_sec,  # 持续时间
        'bytes': flow.byte_count,  # 字节数
        'packets': flow.packet_count,   # 数据包数
        'active': 0,  # 多久未匹配数据包（用于流表项替换）
        'match': flow.match,  # 匹配域
        'priority': flow.priority,   # 优先级
        'is_attack': is_attack,  # 是否为攻击流流表项
        'B_list': [flow.byte_count],    # 报文平均传输字节数组
        'T_list': [flow.duration_sec],    # 报文平均传输间隔数组
    }
    return flow_feature
# 更新流表项特征字典
def update_flow_feature(flow_feature, flow):
    if flow_feature['packets'] == flow.packet_count:
        flow_feature['active'] += 1
    else:
        flow_feature['active'] = 0
    flow_feature['duration'] = flow.duration_sec
    flow_feature['bytes'] = flow.byte_count
    flow_feature['packets'] = flow.packet_count
    if flow.packet_count:
        flow_feature['B_list'].append(flow.byte_count/flow.packet_count)
        flow_feature['T_list'].append(flow.duration_sec/flow.packet_count)
    else:
        flow_feature['B_list'].append(flow.byte_count)
        flow_feature['T_list'].append(flow.duration_sec)

# 保存流表项特征
def save_flow_feature(flow_feature, dpath, time):
    os.makedirs(dpath, exist_ok=True)  # 确保文件目录存在
    file = dpath + '/' + time + '.csv'
    fieldnames = ['ip_src', 'ip_dst', 'port_src', 'port_dst', 'in_port', 'out_port',
                  'duration', 'bytes', 'packets', 'active', 'match', 'priority', 'is_attack', 'B_list', 'T_list']
    with open(file, 'a', newline='', encoding='utf_8_sig') as f:
        csv_write = csv.DictWriter(f, fieldnames=fieldnames)    # fieldnames：列名
        # csv_write.writeheader()
        csv_write.writerows(flow_feature.values())


class MyController(app_manager.RyuApp):  # ryu.base.app_manager.RyuApp
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # 指定协议版本为OpenFlow1.3

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = dict()  # [交换机id][Mac地址]=端口
        self.monitor_thread = hub.spawn(self._monitor)  # 建立线程，定期向交换机发出请求以获取统计数据
        self.switches = {}  # 交换机连接状态   [dpid]=datapath
        # 交换机信息保存父目录
        self.dpath = '/home/zeng/Desktop/Statistic/' + datetime.datetime.strftime(datetime.datetime.now(), '%m%d%H%M%S')
        self.switch_feature = {}  # 保存交换机特征
        self.flow_feature = {}  # 记录流表项信息
        self.flow_limit = [3000, 1500, 3000, 3000, 3000]
        # [dpid]={'match':{源ip、目的ip、源port、目的port、入端口、出端口、持续时间、字节数、数据包数}}
        
        # 检测模型
        self.model_path_graph = '/home/zeng/Desktop/attack/Model/Graph_FIFO.pt'
        self.model_path_node = '/home/zeng/Desktop/attack/Model/Node_FIFO.pt'

    # 控制器和交换机第一次连接时进行初始配置：新增Table_miss流表项
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath  # ev.msg：存储对应事件的OpenFlow数据包 datapath用于描述一个交换网桥，也就是和控制器通信的实体单元
        # 新增Table_miss流表项
        ofproto = datapath.ofproto  # 使用的OpenFlow版本
        parser = datapath.ofproto_parser  # 对应OpenFlow版本的解析协议
        match = parser.OFPMatch()  # OFPMatch()：流表项匹配函数
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]  # 流表项动作（ofproto.OFPP_CONTROLLER：将消息发送给控制器）
        self.add_flow(datapath, 0, match, actions, 0)  # 新增Table_miss流表项（优先级最低，超时值为0）

    # 交换机添加流表项(超时值默认为10)
    def add_flow(self, datapath, priority, match, actions, idle_timeout=10, buffer_id=None):
        # 获取交换机信息
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # 指令集
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]  # OFPIT_APPLY_ACTIONS：必须立即执行的动作
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    priority=priority, match=match, idle_timeout=idle_timeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    priority=priority, match=match, idle_timeout=idle_timeout, instructions=inst)
        # 通过FlowMod新增流表项
        datapath.send_msg(mod)  # datapath.send_msg()函数用于发送数据到指定datapath
        # print("add:", mod)
        # version=0x4,msg_type=0xe,msg_len=0x68,xid=0x2a4c63cb,OFPFlowMod(buffer_id=4294967295,command=0,cookie=0,cookie_mask=0,flags=1,hard_timeout=0,idle_timeout=10,instructions=[OFPInstructionActions(actions=[OFPActionOutput(len=16,max_len=65509,port=6,type=0)],len=24,type=4)],match=OFPMatch(oxm_fields={'in_port': 1, 'eth_dst': '00:00:00:00:00:06', 'eth_src': '00:23:7d:29:b9:74'}),out_group=0,out_port=0,priority=1,table_id=0)

    # 触发PacketIn事件：更新MAC地址表
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']  # 报文入端口
        pkt = packet.Packet(msg.data)
        # eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_type, src, dst = eth.ethertype, eth.src, eth.dst  # 数据包类型，源MAC，目的MAC
        # 判断数据包类型
        if eth_type == ether_types.ETH_TYPE_LLDP:  # 忽略lldp数据包
            return
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port  # 更新MAC地址表，[交换机id][Mac地址]=端口
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # print("self.flow_feature:", len(self.flow_feature[dpid]))

        # 流表已满，执行流表项替换操作
        # print(dpid, "max flow", self.flow_limit[dpid-1], len(self.flow_feature[dpid]))
        if len(self.flow_feature[dpid]) >= self.flow_limit[dpid-1]:
            match = replace_match(self.flow_feature[dpid])
            mod = parser.OFPFlowMod(datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                                    command=ofproto.OFPFC_DELETE, idle_timeout=10, hard_timeout=0, priority=1,
                                    buffer_id=ofproto.OFP_NO_BUFFER, out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY, flags=ofproto.OFPFF_SEND_FLOW_REM, match=match)
            datapath.send_msg(mod)
            # print("mod:", mod)
            # print("Del Dict:", self.flow_feature[dpid][str(match)])
            del self.flow_feature[dpid][str(match)]

        # 判断转发出口
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]  # 目的 MAC 位址若存在于 MAC 地址表，则判断该端口为输出
        else:
            out_port = ofproto.OFPP_FLOOD  # 控制器找不到转发出口
        actions = [parser.OFPActionOutput(out_port)]  # 流表项动作：转发至出口out_port
        match = add_match(parser, in_port, pkt)
        priority = 1
        # 安装流表项
        if out_port != ofproto.OFPP_FLOOD:
            # match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)  #入端口、目的MAC地址、源MAC地址
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, msg.buffer_id)  # 新增流表项（优先级最低，超时值为0）
                return
            else:
                self.add_flow(datapath, priority, match, actions)
        # PacketOut
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ofp_event.EventOFPStateChange：监测交换机连接状态
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:  # MAIN_DISPATCHER：交换机处于连接状态
            if datapath.id not in self.switches:  # 初始化交换机
                print("switch", datapath.id, "connect")
                self.logger.debug('register datapath: %016x', datapath.id)
                self.switches[datapath.id] = datapath
                self.switch_feature[datapath.id] = init_switch_feature(datapath.id)
                # print (self.switch_feature)
                self.flow_feature.setdefault(datapath.id, {})
        elif ev.state == DEAD_DISPATCHER:  # DEAD_DISPATCHER：交换机未连接
            if datapath.id in self.switches:  # 删除交换机
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.switches[datapath.id]
                del self.switch_feature[datapath.id]
                del self.flow_feature[datapath.id]

    # 轮询机制：以1s为间隔执行所需操作
    def _monitor(self):
        number = 0
        self.graph_model = init_Model(self.model_path_graph, 'graph')
        self.node_model = init_Model(self.model_path_graph, 'node')
        while True:
            for datapath in self.switches.values():
                dpid = datapath.id
                self._request_stats(datapath)  # 向交换机请求流表信息和端口信息
                # if number > 0 and number < 701:
                if dpid == 2 and number > 0 and number < 701:
                    time = datetime.datetime.now()
                    # 添加当前交换机特征至文件
                    dpath = self.dpath + '/switch_' + str(dpid)
                    save_switch_feature(self.switch_feature[dpid], self.flow_feature[dpid], dpath,
                                        datetime.datetime.strftime(time, '%Y.%m.%d %H:%M:%S'))
                    # print("switch_feature", dpid, self.switch_feature[dpid])
                    # 保存当前流表项信息至文件
                    dpath = dpath + '/flow'
                    save_flow_feature(self.flow_feature[dpid], dpath, datetime.datetime.strftime(time, '%m%d%H%M%S'))
                    # print("flow_feature", dpid, self.flow_feature[dpid])
                    # 数据收集模块时间耗费
                    time_file = self.dpath + '/switch_' + str(dpid) + '/Time.csv'
                    time_collector = datetime.datetime.now() - time
                    # print('time_collector:', time_collector)

                    # 输出目标交换机当前的模型预测值
                    time_detection_graph = 0
                    time_detection_node = 0
                    if number > 10 and dpid == 2 and len(self.flow_feature[dpid]):
                        guard_start = datetime.datetime.now()
                        graph_prediction = self.graph_model.get_prediction(self.flow_feature[dpid])
                        self.switch_feature[dpid]['is_attack'] = int(graph_prediction)
                        time_detection_graph = datetime.datetime.now()-guard_start
                        # print("Graph:", graph_prediction, time_detection_graph)
                        
                        if graph_prediction:
                            node_prediction = self.node_model.get_prediction(self.flow_feature[dpid])
                            time_detection_node = datetime.datetime.now()-guard_start-time_detection_graph
                            print('Attack Graph', graph_prediction, time_detection_graph, time_detection_node)
                            # 删除识别出的恶意流表项
                            # print("node_prediction:", node_prediction)
                            print(len(node_prediction), len(self.flow_feature[dpid]), len(self.flow_feature[dpid].values()))
                            for index, flow in enumerate(self.flow_feature[dpid].keys()):
                                if node_prediction[index]:
                                    print(index, ' is Attack flow:', node_prediction[index])
                                # else:
                                #     print(index, ' is Normal flow:', node_prediction[index])
                        else:
                            print("Normal Graph:", graph_prediction, time_detection_graph)
        
                    data = [time, time_collector, time_detection_graph, time_detection_node]
                    # print(data)
                    add_to_csv(data, time_file)

                    # CPU占用率, 内存占用率
                    CPU_usage = psutil.cpu_percent(interval=None)
                    # print('CPU_usage%', CPU_usage)
                    Memory = psutil.virtual_memory()
                    Memory_usage = Memory.used # /1024*2=MB
                    Memory_usage_percent = Memory.percent
                    # print('Memory_usage%', Memory_usage)
                    # print([time, CPU_usage, Memory_usage])
                    add_to_csv([time, CPU_usage, Memory_usage, Memory_usage_percent], self.dpath + '/switch_' + str(dpid) + '/Performance.csv')

            hub.sleep(1)
            number += 1

    # 向交换机请求流表信息、流表项信息和端口信息
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)  # 获取流表项信息
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)  # 获取端口信息 OFPP_ANY：所有端口统计数据
        datapath.send_msg(req)

    # 接收流表项信息
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # OFPFlowStatsRequest的响应包
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body  # 列表（每条流表项的统计信息）
        dpid = ev.msg.datapath.id
        for flow in body:
            if flow.priority == 0:  # 不保存Table_miss流表项信息
                continue
            # print(flow)
            # OFPFlowStats(byte_count=0,cookie=0,duration_nsec=450000000,duration_sec=0,flags=1,hard_timeout=0,idle_timeout=10,
            #              instructions=[OFPInstructionActions(actions=[OFPActionOutput(len=16,max_len=65509,port=1,type=0)],len=24,type=4)],length=128,
            #              match=OFPMatch(oxm_fields={'in_port': 3, 'eth_type': 2048, 'ipv4_src': '41.177.26.176', 'ipv4_dst': '10.0.0.6', 'ip_proto': 6, 'tcp_src': 80, 'tcp_dst': 35496}),packet_count=0,priority=1,table_id=0)
            key = str(flow.match)
            if key in self.flow_feature[dpid].keys():
                update_flow_feature(self.flow_feature[dpid][key], flow)
            else:
                self.flow_feature[dpid][key] = init_flow_feature(flow)
        # print(dpid, "flow_feature_number:", len(self.flow_feature[dpid]), len(body))

    # 接收端口信息
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)  # OFPPortStatsRequest的响应包
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # for port in body:
        #     print("PortStats:", dpid, port.port_no, port.rx_packets, port.rx_bytes, port.tx_packets, port.tx_bytes)
        update_port_statistic(self.switch_feature[dpid], body)
        # print(self.switch_feature[dpid])

    # 成功删除流表项
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        # if 'ipv4_src' in msg.match:
        #     print("msg.match:", msg.match['ipv4_src'])
        # else:
        #     print("msg.match:", msg.match)
        #    # OFPMatch(oxm_fields={'in_port': 1, 'eth_src': '00:03:ba:f8:1b:52', 'eth_dst': '00:00:00:00:00:06'})
        dpid = msg.datapath.id
        ofp = msg.datapath.ofproto
        # 流表项删除原因
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
            #print(reason, " Flow removed:", self.flow_feature[dpid][str(msg.match)])
            print(reason, " Flow removed:", msg.match)
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        # 更新删除流表项数量
        if 'ipv4_src' in msg.match and msg.match['ipv4_src'].startswith('250.'):  # 攻击流流表项
            # print("attack flow entry delete")
            self.switch_feature[dpid]['del_attack'] += 1
        else:  # 正常流流表项
            self.switch_feature[dpid]['del_normal'] += 1

        # 删除流表项记录
        if str(msg.match) in self.flow_feature[dpid].keys():
            # print(reason, "Del Dict:", self.flow_feature[dpid][str(msg.match)])
            del self.flow_feature[dpid][str(msg.match)]
        # if dpid == 2:
        #     print(" Flow removed:", reason, len(self.flow_feature[dpid]), msg.match)
