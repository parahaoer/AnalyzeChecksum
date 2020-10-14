#抑制scapy导入所出现的报错信息

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

'''
构造ICMP数据包，在Linux系统下能够成功发包，而Windows系统下ICMP数据包发不出去。

'''

#导入相应的包
from scapy.all import *

from random import randint


def ping_once(host):

    # 随机产生一个1-65535的icmp的id位
    icmp_id=randint(1,65535)

    # 随机产生一个1-65535的icmp的序列号
    icmp_seq=randint(1,65535)

    #铸造数据包
    # payload = b''

    # for i in range(0,288):
    #     payload += b'\xFF'
    # payload = b'\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69'
    payload = b'\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68'
    print(payload)
    packet=IP(dst=host,ttl=64)/ICMP(id=icmp_id,seq=icmp_seq)/payload
    print(packet)
    #发送数据包
    ping=sr(packet,timeout=2)
    print(ping[0].res)
    #如果收到回复则代表ping成功，成功就以退出码3退出(便于后续用来判断此进程是否成功)

    if ping:

        os._exit(3)

if __name__ == '__main__':

    ping_once(sys.argv[1])