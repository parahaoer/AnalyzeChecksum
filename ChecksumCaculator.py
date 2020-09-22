import binascii


class ChecksumCaculator():
    def chesksum(self, icmp_packet):
        """
        校验
        """
        n = len(icmp_packet)
        m = n % 2  #判断data长度是否是偶数字节
        sum = 0  #记录(十进制)相加的结果
        for i in range(0, n - m, 2):  #将每两个字节(16位)相加（二进制求和）直到最后得出结果
            sum += icmp_packet[i] + (icmp_packet[i + 1] << 8)  #传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
        if m:  #传入的data长度是奇数，将执行，且把这个字节（8位）加到前面的结果
            sum += icmp_packet[-1]
        #将高于16位与低16位相加
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)  #如果还有高于16位，将继续与低16位相加
        answer = ~sum & 0xffff  #对sum取反(返回的是十进制)
        #主机字节序转网络字节序列（参考小端序转大端序）
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer  #最终返回的结果就是wireshark里面看到的checksum校验和

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
