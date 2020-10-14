# 抑制scapy导入所出现的报错信息
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


'''
构造ICMP数据包，在Linux系统下能够成功发包，而Windows系统下ICMP数据包发不出去。
参考：https://blog.csdn.net/rootkitylp/article/details/53098832
'''

# 导入相应的包
from scapy.all import *
from random import randint
import six

def ping_once(host, payload):

    # 随机产生一个1-65535的icmp的id位
    icmp_id=randint(1,65535)

    # 随机产生一个1-65535的icmp的序列号
    icmp_seq=randint(1,65535)

    packet=IP(dst=host,ttl=64)/ICMP(id=icmp_id,seq=icmp_seq)/payload
    
    # print(packet)
    # 发送数据包
    ping=sr(packet,timeout=2)
    print(ping[0].res)
    # 如果收到回复则代表ping成功，成功就以退出码3退出(便于后续用来判断此进程是否成功)

def iping(host):
    # 铸造数据包
    payload = b''
    for i in range(0, 1472):

        random_byte = randint(1, 255)
        # 将十进制数转换成单个字节
        cur_bytes = six.int2byte(random_byte)

        payload += cur_bytes

        ping_once(host, payload)


if __name__ == '__main__':

    iping(sys.argv[1])