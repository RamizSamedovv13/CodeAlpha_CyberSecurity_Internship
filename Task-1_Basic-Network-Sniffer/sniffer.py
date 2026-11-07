#!/usr/bin/env python3
import argparse
from scapy.all import (sniff, IP, IPv6, TCP, UDP, ICMP, ARP,
                       DNS, DNSQR, Raw, PcapWriter)

ICMP_TYPES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    8: "Echo (ping) request",
    11: "Time-to-live exceeded",
}
TCP_FLAGS = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}

start_time = None
counter = 0
writer = None
args = None


def hexdump(data, length=64):
    data = bytes(data)[:length]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"        {i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def describe(pkt):
    """Paketdən (src, dst, protokol, info) qaytarır."""
    # ARP
    if ARP in pkt:
        a = pkt[ARP]
        if a.op == 1:
            info = f"Who has {a.pdst}? Tell {a.psrc}"
        else:
            info = f"{a.psrc} is at {a.hwsrc}"
        return a.psrc, a.pdst, "ARP", info

    # IP qatı
    if IP in pkt:
        ip = pkt[IP]
        src, dst, ttl = ip.src, ip.dst, ip.ttl
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst, ttl = ip.src, ip.dst, ip.hlim
    else:
        return pkt.src, pkt.dst, pkt.lastlayer().name, ""

    # ICMP
    if ICMP in pkt:
        ic = pkt[ICMP]
        name = ICMP_TYPES.get(ic.type, f"type={ic.type}")
        info = f"{name:<18} id=0x{ic.id:04x}, seq={ic.seq}, ttl={ttl}"
        return src, dst, "ICMP", info

    # DNS
    if DNS in pkt:
        d = pkt[DNS]
        qname = d[DNSQR].qname.decode(errors="ignore") if DNSQR in d else ""
        if d.qr == 0:
            info = f"Standard query 0x{d.id:04x} {qname}"
        else:
            info = f"Standard query response 0x{d.id:04x} {qname}"
        return src, dst, "DNS", info

    # TCP
    if TCP in pkt:
        t = pkt[TCP]
        flags = ", ".join(TCP_FLAGS[f] for f in str(t.flags) if f in TCP_FLAGS)
        info = (f"{t.sport} → {t.dport} [{flags}] "
                f"Seq={t.seq} Ack={t.ack} Win={t.window}")
        proto = "TCP"
        if Raw in pkt:
            first = bytes(pkt[Raw].load).split(b"\r\n")[0][:60]
            if first.startswith((b"GET", b"POST", b"HTTP", b"PUT", b"HEAD")):
                proto = "HTTP"
                info = first.decode(errors="ignore")
        elif t.dport == 443 or t.sport == 443:
            proto = "TCP"
        return src, dst, proto, info

    # UDP
    if UDP in pkt:
        u = pkt[UDP]
        return src, dst, "UDP", f"{u.sport} → {u.dport} Len={u.len - 8}"

    return src, dst, str(ip.name), ""


def process_packet(pkt):
    global start_time, counter
    counter += 1

    t = float(pkt.time)
    if start_time is None:
        start_time = t
    rel = t - start_time

    src, dst, proto, info = describe(pkt)
    print(f"{counter:>5} {rel:>12.6f} {src:>15} → {dst:<15} "
          f"{proto:<5} {len(pkt):>4} {info}")

    if args.hexdump and Raw in pkt:
        print(hexdump(pkt[Raw].load))

    if writer:
        writer.write(pkt)


def main():
    global args, writer
    p = argparse.ArgumentParser(description="Sadə paket analizatoru")
    p.add_argument("-i", "--iface", help="interfeys (məs: eth0)")
    p.add_argument("-c", "--count", type=int, default=0, help="paket sayı (0 = sonsuz)")
    p.add_argument("-f", "--filter", help="BPF filtr (məs: 'icmp', 'tcp port 80')")
    p.add_argument("-x", "--hexdump", action="store_true", help="payload-u hex+ASCII göstər")
    p.add_argument("-w", "--write", help=".pcap faylına yaz")
    args = p.parse_args()

    if args.write:
        writer = PcapWriter(args.write, append=False, sync=True)

    print(f"Capturing on '{args.iface or 'default'}'")
    try:
        sniff(iface=args.iface, filter=args.filter, prn=process_packet,
              count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    print(f"\n{counter} packets captured")


if __name__ == "__main__":
    main()
