from PcapAnalyzer import PcapAnalyzer
from ChecksumCaculator import ChecksumCaculator

if __name__ == "__main__":
    ip_pairs_dict = {}
    pcapAnalyzer = PcapAnalyzer(ip_pairs_dict)
    pcapAnalyzer.get_filelist('pcap_dir/linux_slice_ff_request.pcap')
    '''
    将icmp分片组包得到一个完整的包含ICMP首部的ICMP packet， 对icmp packet计算校验和。
    可以算出该校验和在分片之间已经计算好了，是在传输过程中对数据包分片的。
    '''
    for ip_key in ip_pairs_dict:
        icmp_requst_bytes = bytes()
        
        icmp_requst_slice_list = ip_pairs_dict[ip_key]
        for icmp_requst_slice in icmp_requst_slice_list:
            icmp_requst_slice_bytes = icmp_requst_slice.payload.payload.original
            icmp_requst_bytes += icmp_requst_slice_bytes
        
        checksumCaculator = ChecksumCaculator()
        checksumCaculator.caculateChecksum(icmp_requst_bytes) 



