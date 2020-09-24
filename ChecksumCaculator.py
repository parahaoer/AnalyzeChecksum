import binascii


class ChecksumCaculator():
    # def chesksum(self, icmp_packet):
    #     """
    #     校验
    #     """
    #     n = len(icmp_packet)
    #     m = n % 2  #判断data长度是否是偶数字节
    #     sum = 0  #记录(十进制)相加的结果
    #     for i in range(0, n - m, 2):  #将每两个字节(16位)相加（二进制求和）直到最后得出结果
    #         sum += icmp_packet[i] + (icmp_packet[i + 1] << 8)  #传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
    #     if m:  #传入的data长度是奇数，将执行，且把这个字节（8位）加到前面的结果
    #         sum += icmp_packet[-1]
    #     #将高于16位与低16位相加
    #     print('{:d} --->  {:x}'.format(sum, sum))
    #     sum = (sum >> 16) + (sum & 0xffff)
    #     print('{:d} --->  {:x}'.format(sum, sum))
    #     sum += (sum >> 16)  #如果还有高于16位，将继续与低16位相加
    #     print('{:d} --->  {:x}'.format(sum, sum))
    #     answer = ~sum & 0xffff  #对sum取反(返回的是十进制)
    #     #主机字节序转网络字节序列（参考小端序转大端序）
    #     answer = answer >> 8 | (answer << 8 & 0xff00)
    #     print('{:d} --->  {:x}'.format(answer, answer))
    #     return answer  #最终返回的结果就是wireshark里面看到的checksum校验和
    '''
    例子：
    对于ICMP报文0800 0000 0001 0001 6162 6364 6566 6768 696a 6b6c 6d6e 6f70 7172 7374 7576 7761 6263 6465 6667 6869，
    将校验和所占的2个字节设置为0，然后每2个字节作为一个数来求和，如下所示：
    0x0800 + 0x0000 + 0x0001 + 0x0001 + 0x6162 + 0x6364 + 0x6566 + 0x6768 + 0x696a + \
    0x6b6c + 0x6d6e + 0x6f70 + 0x7172 + 0x7374 + 0x7576 + 0x7761 + 0x6263 + 0x6465 + 0x6667 + 0x6869
    结果为0x6B29F, 然后将高16位与低16位相加，即0x6 + 0xB29F，得到0xB2A5 ，如果还有高16位，就继续加上去，
    但当前例子中0xB2A5没有高16位，所以不需要相加。
    将0xB2A5取反得到校验和 0x4D5A

    '''
    def chesksum(self, icmp_packet):

        n = len(icmp_packet)
        m = n % 2  # 判断data长度是否是偶数字节
        sum = 0  # 记录(十进制)相加的结果
        for i in range(0, n - m, 2):  # 将每两个字节(16位)相加（二进制求和）直到最后得出结果
            sum += (icmp_packet[i] << 8) + icmp_packet[i + 1]  # 传入报文以每两个字节，第一字节在高位，第二个字节在低位
        if m:  # 传入的报文长度是奇数，将执行，且把这个字节移到高8位后加到前面的结果
            sum += (icmp_packet[-1] << 8)
        print('sum= {:d} --->  {:x}'.format(sum, sum))
        # 将高16位与低16位相加
        sum = (sum >> 16) + (sum & 0xffff)
        print('low+high= {:d} --->  {:x}'.format(sum, sum))
        sum += (sum >> 16)  # 如果还有高于16位，将高16位加到前面的结果
        print('high= {:d} --->  {:x}'.format(sum, sum))
        answer = ~sum & 0xffff  # 对sum取反(返回的是十进制)
        return answer

    def caculateChecksum(self, icmp_packet):

        icmp_bytes_array = bytearray(icmp_packet)
        icmp_bytes_array[2] = 0
        icmp_bytes_array[3] = 0
        cks = self.chesksum(icmp_bytes_array)
        print('{:d} --->  {:x}'.format(cks, cks))

    def caculateReplyChecksum(self, icmp_packet):

        replyChecksum = self.convertChecksumToInt(icmp_packet) + 0x0800
        replyChecksum = replyChecksum - 0xffff if (replyChecksum > 0xffff) else replyChecksum
        print('{:d} --->  {:x}'.format(replyChecksum, replyChecksum))
        return replyChecksum

    def convertChecksumToInt(self, icmp_packet):
        checkSum_bytes = icmp_packet[2:4]
        checkSum = binascii.b2a_hex(checkSum_bytes)
        return int(checkSum, 16)
