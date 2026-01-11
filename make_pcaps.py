from scapy.all import IP, TCP, wrpcap, Raw

def make_flow_packets(src, dst, sport, dport, payload_size, chunk=1400, start_seq=1):
    pkts = []
    seq = start_seq
    remaining = payload_size
    while remaining > 0:
        n = min(chunk, remaining)
        pkts.append(
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags="PA", seq=seq) /
            Raw(load=b"A" * n)
        )
        seq += n
        remaining -= n
    return pkts

def main():
    # normal: mały HTTPS (443) + trochę HTTP (80)
    normal = []
    normal += make_flow_packets("10.0.0.10", "1.1.1.1", 40000, 443, payload_size=20_000)
    normal += make_flow_packets("10.0.0.11", "8.8.8.8", 40001, 80, payload_size=5_000)

    # suspicious: duży transfer na 443 (ważne: > 1_000_000 src2dst_bytes)
    suspicious = []
    suspicious += make_flow_packets("10.0.0.66", "2.2.2.2", 45000, 443, payload_size=1_300_000)
    # dorzućmy coś “normalnego” obok, żeby było co porównać
    suspicious += make_flow_packets("10.0.0.12", "9.9.9.9", 40002, 443, payload_size=15_000)

    import os
    os.makedirs("pcaps", exist_ok=True)
    wrpcap("pcaps/normal.pcap", normal)
    wrpcap("pcaps/suspicious.pcap", suspicious)
    print("OK: pcaps/normal.pcap, pcaps/suspicious.pcap")

if __name__ == "__main__":
    main()
