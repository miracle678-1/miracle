package com.mamba.pcap;

import java.util.ArrayList;
import java.util.List;

/**
 * 纯 Java 实现的 pcapng 文件解析器（不依赖 pcap4j 等第三方库）。
 *
 * <p>核心思想：基于 DPI（深度包检测）逐层"剥包"——
 * 遍历 pcapng 的各个 Block（块），对每个 Enhanced Packet Block（增强包块）
 * 依次解析以太网头 → IPv4 / ARP 头 → TCP / UDP / ICMP 头，
 * 最终提取出五元组（源 IP、源端口、目的 IP、目的端口、协议）和帧长度。
 *
 * <p>本实验的抓包文件链路类型均为 Ethernet（LinkType = 1），故只处理该类型。
 * 同时读取接口的时间戳精度选项（if_tsresol），把纳秒级时间戳正确换算成毫秒。
 */
public final class PcapNgParser {

    // pcapng 块类型常量（块类型字段为 4 字节小端整数）
    private static final int BLOCK_IDB = 0x00000001; // 接口描述块（Interface Description Block）
    private static final int BLOCK_EPB = 0x00000006; // 增强包块（Enhanced Packet Block）

    // 以太网帧 EtherType 字段取值（网络字节序，大端）
    private static final int ETHERTYPE_IPV4 = 0x0800; // IPv4
    private static final int ETHERTYPE_ARP = 0x0806;  // ARP
    private static final int ETHERTYPE_VLAN = 0x8100; // 802.1Q VLAN 标签
    private static final int ETHERTYPE_IPV6 = 0x86DD; // IPv6

    /**
     * 解析结果回调接口：解析器每解析出一个数据包，就回调一次。
     * 由调用方（TrafficAnalysisService）决定如何消费结果，实现"解析"与"统计"的解耦。
     */
    public interface PacketHandler {
        void onPacket(PacketInfo packet);
    }

    /**
     * 单个抓包接口的描述信息（对应 pcapng 的 IDB 块）。
     */
    private static final class IfInfo {
        int linkType = 1;      // 链路类型，1 = 以太网
        int tsresol = 6;       // 时间戳精度（十进制位数），默认 6 表示微秒（10^-6 秒）
        boolean tsresolBinary = false; // 为 true 时 tsresol 表示 2 的幂次，否则为 10 的幂次
    }

    private PcapNgParser() {
    }

    /**
     * 解析整个 pcapng 文件。
     *
     * <p>pcapng 由一系列块组成，每个块的结构固定为：
     * <pre>
     *   [块类型(4字节)] [块总长度(4字节)] [块体(变长)] [块总长度(4字节，重复)]
     * </pre>
     * 块总长度前后各出现一次，便于向前/向后遍历；块结构字段均为小端。
     *
     * @param data       pcapng 文件的原始字节
     * @param attackType 该文件对应的攻击类型标签（如 "SYN Flood"）
     * @param handler    每解析出一个包就回调该接口
     */
    public static void parse(byte[] data, String attackType, PacketHandler handler) {
        List<IfInfo> interfaces = new ArrayList<>();
        int len = data.length;
        int pos = 0;

        // 主循环：逐个读取块
        while (pos + 12 <= len) {
            int blockType = readIntLE(data, pos);        // 块类型
            int blockLen = readIntLE(data, pos + 4);     // 块总长度
            if (blockLen < 12 || pos + blockLen > len) { // 块长非法，说明文件损坏，停止
                break;
            }
            int body = pos + 8;                          // 块体起始位置（跳过 4+4 字节头）

            if (blockType == BLOCK_IDB && body + 8 <= len) {
                // 接口描述块：记录该接口的链路类型、时间戳精度等信息
                interfaces.add(readInterface(data, body, pos + blockLen));
            } else if (blockType == BLOCK_EPB && body + 20 <= len) {
                // 增强包块：真正的数据包
                // 块体前 20 字节依次为：接口ID(4) + 时间戳高32位(4) + 时间戳低32位(4)
                //                      + 捕获长度(4) + 原始长度(4)
                int ifaceId = readIntLE(data, body);
                int tsHigh = readIntLE(data, body + 4);
                int tsLow = readIntLE(data, body + 8);
                int capLen = readIntLE(data, body + 12); // 捕获长度（实际存入文件的字节数）
                int pktPos = body + 20;                  // 包数据的起始位置

                if (capLen > 0 && pktPos + capLen <= len) {
                    // 拼接 64 位时间戳原始值（无符号）
                    long tsRaw = ((long) tsHigh << 32) | (tsLow & 0xFFFFFFFFL);
                    // 根据接口ID取出对应的接口信息，换算时间戳为毫秒
                    IfInfo ifInfo = (ifaceId >= 0 && ifaceId < interfaces.size())
                            ? interfaces.get(ifaceId) : new IfInfo();
                    long tsMs = tsToMillis(tsRaw, ifInfo);
                    if (ifInfo.linkType == 1) { // 只处理以太网链路
                        parseEthernet(data, pktPos, capLen, tsMs, attackType, handler);
                    }
                }
            }

            pos += blockLen; // 跳到下一个块
        }
    }

    /**
     * 解析接口描述块（IDB），读取链路类型和 if_tsresol 时间戳精度选项。
     *
     * <p>IDB 块体结构：链路类型(2) + 保留(2) + 快照长度(4) + 若干选项。
     * 每个选项结构为：code(2) + 长度(2) + 值(变长，4字节对齐)。
     * 其中 code=9 为 if_tsresol 选项。
     */
    private static IfInfo readInterface(byte[] b, int body, int blockEnd) {
        IfInfo info = new IfInfo();
        info.linkType = readUShortLE(b, body); // 链路类型

        int opt = body + 8;                      // 选项区起始（跳过 8 字节固定头）
        int end = blockEnd - 4;                  // 去掉块尾重复的 4 字节块长
        while (opt + 4 <= end) {
            int code = readUShortLE(b, opt);     // 选项代码
            int olen = readUShortLE(b, opt + 2); // 选项值长度
            if (code == 0) {                     // code=0 表示选项结束
                break;
            }
            if (code == 9 && olen >= 1 && opt + 4 + 1 <= end) {
                // if_tsresol：值最高位为 1 表示 2 的幂次，否则表示 10 的幂次
                int tsr = b[opt + 4] & 0xFF;
                if ((tsr & 0x80) != 0) {
                    info.tsresol = tsr & 0x7F;
                    info.tsresolBinary = true;
                } else {
                    info.tsresol = tsr;
                    info.tsresolBinary = false;
                }
            }
            opt += 4 + ((olen + 3) & ~3);        // 跳过当前选项（值长度按 4 字节对齐）
        }
        return info;
    }

    /**
     * 把 pcapng 的 64 位时间戳原始值换算为毫秒。
     *
     * <p>原始值的单位是 10^-tsresol 秒（十进制）或 2^-tsresol 秒（二进制），
     * 要得到毫秒需除以 10^(tsresol-3) 或 2^(tsresol-3)。
     */
    private static long tsToMillis(long raw, IfInfo info) {
        if (info.tsresolBinary) {
            int shift = info.tsresol - 3;       // 用移位代替 2 的幂次除法
            if (shift >= 0) {
                return raw >>> shift;
            }
            return raw << (-shift);
        }
        int exp = info.tsresol - 3;             // 十进制：10 的幂次
        long factor = 1;
        for (int i = 0; i < Math.abs(exp); i++) {
            factor *= 10;
        }
        return exp >= 0 ? raw / factor : raw * factor;
    }

    /**
     * 解析以太网帧头，根据 EtherType 字段分发给上层协议解析。
     *
     * <p>以太网头共 14 字节：目的MAC(6) + 源MAC(6) + EtherType(2)。
     * 若 EtherType 为 0x8100 表示带 VLAN 标签，需再跳过 4 字节读取内层 EtherType。
     */
    private static void parseEthernet(byte[] b, int start, int frameLen, long tsMs,
                                      String attack, PacketHandler h) {
        int end = start + frameLen;
        if (frameLen < 14) {
            return; // 帧太短，不是合法以太网帧
        }
        int etherType = readUShortBE(b, start + 12); // EtherType 在头偏移 12 处
        int netPos = start + 14;
        if (etherType == ETHERTYPE_VLAN && frameLen >= 18) {
            // VLAN 帧：再往后读 2 字节才是真正的 EtherType
            etherType = readUShortBE(b, start + 16);
            netPos = start + 18;
        }

        switch (etherType) {
            case ETHERTYPE_IPV4 -> parseIpv4(b, netPos, end, frameLen, tsMs, attack, h);
            case ETHERTYPE_ARP -> parseArp(b, netPos, end, frameLen, tsMs, attack, h);
            case ETHERTYPE_IPV6 ->
                    // IPv6 仅记录协议类型，不解析具体地址与端口
                    h.onPacket(new PacketInfo(tsMs, "-", 0, "-", 0, "IPv6", frameLen, attack));
            default -> {
                // 其他类型的以太网负载不处理
            }
        }
    }

    /**
     * 解析 IPv4 头并提取五元组。
     *
     * <p>IPv4 头关键字段偏移（单位字节）：
     * <pre>
     *   0     : 版本(4bit) + 首部长度 IHL(4bit)
     *   2-3   : 总长度
     *   9     : 协议号（6=TCP, 17=UDP, 1=ICMP）
     *   12-15 : 源 IP
     *   16-19 : 目的 IP
     * </pre>
     * 首部长度 IHL 以 4 字节为单位，需乘以 4 得到实际字节数。
     */
    private static void parseIpv4(byte[] b, int pos, int end, int frameLen, long tsMs,
                                  String attack, PacketHandler h) {
        if (pos + 20 > end) {
            return; // 不足 20 字节的固定头
        }
        int ihl = (b[pos] & 0x0F) * 4;   // 首部长度（取低 4 位，单位 4 字节）
        if (ihl < 20 || pos + ihl > end) {
            return; // 首部长度非法
        }
        int proto = b[pos + 9] & 0xFF;   // 协议号
        String src = readIpv4(b, pos + 12); // 源 IP
        String dst = readIpv4(b, pos + 16); // 目的 IP
        int totalLen = readUShortBE(b, pos + 2); // IP 总长度

        int l4Pos = pos + ihl;           // 传输层头起始位置（IP 头之后）
        int l4End = Math.min(pos + totalLen, end);
        int srcPort = 0;
        int dstPort = 0;
        String protocol;

        if (proto == 6) {                // TCP：端口在头前 4 字节
            protocol = "TCP";
            if (l4Pos + 4 <= l4End) {
                srcPort = readUShortBE(b, l4Pos);
                dstPort = readUShortBE(b, l4Pos + 2);
            }
        } else if (proto == 17) {        // UDP：端口同样在头前 4 字节
            protocol = "UDP";
            if (l4Pos + 4 <= l4End) {
                srcPort = readUShortBE(b, l4Pos);
                dstPort = readUShortBE(b, l4Pos + 2);
            }
        } else if (proto == 1) {         // ICMP：无端口概念
            protocol = "ICMP";
        } else {
            protocol = "OTHER";
        }

        h.onPacket(new PacketInfo(tsMs, src, srcPort, dst, dstPort, protocol, frameLen, attack));
    }

    /**
     * 解析 ARP 报文。
     *
     * <p>ARP 头关键字段偏移（单位字节）：
     * <pre>
     *   6-7   : 操作码（1=请求, 2=应答）
     *   14-17 : 发送方 IP
     *   24-27 : 目标 IP
     * </pre>
     * ARP 无端口概念，端口字段填 0。
     */
    private static void parseArp(byte[] b, int pos, int end, int frameLen, long tsMs,
                                 String attack, PacketHandler h) {
        if (pos + 28 > end) {
            return; // ARP 头固定 28 字节
        }
        String senderIp = readIpv4(b, pos + 14); // 发送方 IP
        String targetIp = readIpv4(b, pos + 24); // 目标 IP
        h.onPacket(new PacketInfo(tsMs, senderIp, 0, targetIp, 0, "ARP", frameLen, attack));
    }

    /** 小端读取 4 字节有符号整数（用于 pcapng 块结构字段）。 */
    private static int readIntLE(byte[] b, int p) {
        return (b[p] & 0xFF)
                | ((b[p + 1] & 0xFF) << 8)
                | ((b[p + 2] & 0xFF) << 16)
                | ((b[p + 3] & 0xFF) << 24);
    }

    /** 小端读取 2 字节无符号整数（用于 pcapng 块结构字段）。 */
    private static int readUShortLE(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    /** 大端（网络字节序）读取 2 字节无符号整数，用于以太网/IP/TCP/UDP/ARP 头字段。 */
    private static int readUShortBE(byte[] b, int p) {
        return ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
    }

    /** 把 4 字节 IPv4 地址拼接成点分十进制字符串（如 "192.168.100.10"）。 */
    private static String readIpv4(byte[] b, int p) {
        return (b[p] & 0xFF) + "." + (b[p + 1] & 0xFF) + "."
                + (b[p + 2] & 0xFF) + "." + (b[p + 3] & 0xFF);
    }
}
