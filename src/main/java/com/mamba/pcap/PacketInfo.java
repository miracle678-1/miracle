package com.mamba.pcap;

/**
 * 单个已解析数据包的模型，封装了网络五元组及其他可视化所需字段。
 *
 * <p>五元组 = 源 IP + 源端口 + 目的 IP + 目的端口 + 协议。
 * 使用 Java 17 的 record（不可变数据类），Jackson 会自动序列化为 JSON 返回给前端。
 *
 * <p>说明：ARP、ICMP 等协议没有端口概念，其端口字段填 0（前端显示为 "-"）；
 * IPv6 数据包不解析具体地址，源/目的 IP 用 "-" 占位。
 */
public record PacketInfo(
        long timestamp,   // 抓包时间戳（毫秒，自 1970-01-01 起）
        String srcIp,     // 源 IP 地址
        int srcPort,      // 源端口
        String dstIp,     // 目的 IP 地址
        int dstPort,      // 目的端口
        String protocol,  // 协议类型（TCP / UDP / ICMP / ARP / IPv6 / OTHER）
        int length,       // 帧长度（字节）
        String attackType // 攻击类型标签（SYN Flood / ICMP Flood / ARP Spoof）
) {
}
