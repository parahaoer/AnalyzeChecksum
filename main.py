from PcapAnalyzer import PcapAnalyzer
from ICMPPairsGenerator import ICMPPairsGenerator
from ChecksumCaculator import ChecksumCaculator

if __name__ == "__main__":

    count = 0
    checksumCaculator = ChecksumCaculator()

    ip_pairs_dict = {}
    pcapAnalyzer = PcapAnalyzer(ip_pairs_dict)
    pcapAnalyzer.get_filelist('pcap_dir/positive-icmp/ICMPTransmitter')

    for ip_key in ip_pairs_dict:
        ip_pair_datas = ip_pairs_dict[ip_key]
        
        icmp_pairs_dict = {}
        iCMPPairsGenerator = ICMPPairsGenerator()
        iCMPPairsGenerator.getICMPPair(ip_pair_datas, icmp_pairs_dict)

        for icmp_key in icmp_pairs_dict:
            icmp_packet_list = icmp_pairs_dict[icmp_key]

            caculateReplyChecksum = 0
            has_request = False
            for icmp_packet in icmp_packet_list:
                icmp_fileds = icmp_packet.fields
                icmp_type = icmp_fileds['type']
                if icmp_type == 8:
                    has_request = True
                    caculateReplyChecksum = checksumCaculator.caculateReplyChecksum(icmp_packet.original)
                if has_request and icmp_type == 0:
                    replyChecksum = checksumCaculator.convertChecksumToInt(icmp_packet.original)
                    if caculateReplyChecksum != replyChecksum:
                        count += 1
                        print(icmp_packet.payload.original.hex())
    
    print(count)
    










