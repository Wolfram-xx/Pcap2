import argparse
from scapy.all import rdpcap


def load_packets(pcap_file):
    """Загружает пакеты из pcap файла и возвращает список (timestamp, raw_data)"""
    packets = rdpcap(pcap_file)
    return [(pkt.time, bytes(pkt)) for pkt in packets]


def find_matching_intervals(packets1, packets2, min_seq):
    """Находит совпадающие интервалы пакетов между двумя списками пакетов"""
    matches = []
    i, j = 0, 0

    while i < len(packets1):
        while j < len(packets2):
            match_seq = []
            start_i, start_j = i, j

            while i < len(packets1) and j < len(packets2) and packets1[i][1] == packets2[j][1]:
                match_seq.append((packets1[i][0], packets2[j][0]))
                i += 1
                j += 1

            if len(match_seq) >= min_seq:
                matches.append((start_i, start_j, match_seq))

            j += 1
        i += 1
        j = 0  # Сбрасываем j для нового прохода

    return matches


def main():
    parser = argparse.ArgumentParser(description="Find matching packet intervals in two pcap files")
    parser.add_argument("pcap1", help="Path to first pcap file")
    parser.add_argument("pcap2", help="Path to second pcap file")
    parser.add_argument("--min_seq", type=int, required=True, help="Minimum number of consecutive matching packets")
    parser.add_argument("--intervals", type=int, nargs='+', help="Specific interval(s) to display", default=[])
    args = parser.parse_args()

    packets1 = load_packets(args.pcap1)
    packets2 = load_packets(args.pcap2)
    matches = find_matching_intervals(packets1, packets2, args.min_seq)

    print(f"Total matching intervals: {len(matches)}")

    for idx, (start_i, start_j, match_seq) in enumerate(matches):
        if not args.intervals or idx + 1 in args.intervals:
            print(f"Interval {idx + 1}:")
            print(f"  Matching packets: {len(match_seq)}")
            print(f"  First match - File1 Packet #{start_i}, Timestamp: {match_seq[0][0]}")
            print(f"  First match - File2 Packet #{start_j}, Timestamp: {match_seq[0][1]}")
            print("-------------------------------")


if __name__ == "__main__":
    main()