package com.mamba.service;

import com.mamba.pcap.PacketInfo;
import com.mamba.pcap.PcapNgParser;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 流量分析服务：业务核心层。
 *
 * <p>负责从 classpath 加载 pcapng 抓包文件，调用 {@link PcapNgParser} 解析每一个数据包，
 * 并聚合出可视化所需的四类统计结果：
 * <ol>
 *   <li>协议类型分布</li>
 *   <li>数据包大小分布</li>
 *   <li>异常端口流量（445 / 136 / 137 / 138 / 139）</li>
 *   <li>按 IP 地址统计流量</li>
 * </ol>
 *
 * <p>设计要点：懒加载 + 双重检查锁（首次访问才解析，之后命中缓存）；流式聚合（边读边累加，
 * 不把百万级数据包全部留在内存）；仅采样保留每文件前若干条五元组明细供表格展示。
 */
@Service
public class TrafficAnalysisService {

    /** 数据包大小分桶区间（符合实验要求）。 */
    private static final String[] SIZE_BUCKETS = {
            "<=64", "65-127", "128-255", "256-511", "512-1023", "1024-1517", ">=1518"
    };

    /** 需要监控的异常端口。 */
    private static final int[] ABNORMAL_PORTS = {445, 136, 137, 138, 139};

    /** 每个文件最多保留的采样数据包数量（用于五元组明细展示）。 */
    private static final int SAMPLE_LIMIT_PER_FILE = 3000;

    /** 按 IP 统计时返回的前 N 个 IP。 */
    private static final int TOP_IP_LIMIT = 20;

    /** 用于同步（懒加载与统计读写）的锁对象。 */
    private final Object lock = new Object();

    // —— 总体统计 ——
    private long totalPackets = 0;   // 数据包总数
    private long totalBytes = 0;     // 总流量字节数
    private int uniqueIpCount = 0;   // 独立 IP 数量

    // —— 各类统计的中间结果 ——
    private final List<PacketInfo> samplePackets = new ArrayList<>();     // 采样保留的明细
    private final Map<String, Long> protocolCount = new LinkedHashMap<>(); // 协议 -> 数量
    private final Map<String, Long> sizeCount = new LinkedHashMap<>();     // 大小分桶 -> 数量
    private final Map<Integer, Long> portCount = new LinkedHashMap<>();   // 异常端口 -> 数量
    private final Map<String, IpStat> ipStats = new LinkedHashMap<>();    // IP -> 统计
    private final List<String> loadedFiles = new ArrayList<>();           // 已加载文件名
    private final Map<String, String> attackLabels = new LinkedHashMap<>(); // 文件名 -> 攻击类型

    private boolean loaded = false; // 是否已完成加载解析

    /** 单个 IP 的统计信息（数据包数 + 字节数）。 */
    private static final class IpStat {
        long packets;
        long bytes;
    }

    /** 获取全部统计结果（供前端图表使用）。 */
    public Map<String, Object> getStats() {
        ensureLoaded();//加载数据
        synchronized (lock) {
            return buildStatsResponse();
        }
    }

    /**
     * 分页获取五元组明细列表（供前端表格使用）。
     *
     * @param page 页码，从 0 开始
     * @param size 每页条数
     */
    public Map<String, Object> getPackets(int page, int size) {
        ensureLoaded();
        synchronized (lock) {
            int total = samplePackets.size();
            int from = Math.min(page * size, total);
            int to = Math.min(from + size, total);
            List<PacketInfo> slice = new ArrayList<>(samplePackets.subList(from, to));

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("total", total);                 // 采样包总数
            result.put("sampled", total < totalPackets); // 是否仅采样
            result.put("totalPackets", totalPackets);   // 真正的全量包数
            result.put("page", page);
            result.put("size", size);
            result.put("items", slice);
            return result;
        }
    }

    /**
     * 强制重新解析：清空缓存后重新加载 classpath 下的所有 pcapng 文件。
     * 用于抓包文件被替换/新增后无需重启即可刷新数据。
     */
    public Map<String, Object> reload() {
        synchronized (lock) {
            reset();
            loadFromClasspath();
            loaded = true;
            return buildStatsResponse();
        }
    }

    /**
     * 确保数据已加载（懒加载 + 双重检查锁）。
     * 首次调用时解析，之后直接命中缓存，避免重复解析百万级数据包。
     */
    private void ensureLoaded() {
        if (loaded) {
            return;
        }//已加载则直接返回
        synchronized (lock) {//获取锁
            if (!loaded) {
                loadFromClasspath();//加载数据
                loaded = true;
            }
        }
    }

    /** 清空所有统计数据（供 reload 使用）。 */
    private void reset() {
        totalPackets = 0;
        totalBytes = 0;
        uniqueIpCount = 0;
        samplePackets.clear();
        protocolCount.clear();
        sizeCount.clear();
        portCount.clear();
        ipStats.clear();
        loadedFiles.clear();
        attackLabels.clear();
    }

    /** 从 classpath 的 pcaps 目录加载所有 pcapng 文件并逐个解析。 */
    private void loadFromClasspath() {
        try {
            Resource[] resources = new PathMatchingResourcePatternResolver()
                    .getResources("classpath:pcaps/*.pcapng");
            for (Resource resource : resources) {
                String filename = resource.getFilename() == null ? "unknown" : resource.getFilename();
                String label = attackLabelFor(filename); // 根据文件名推断攻击类型
                attackLabels.put(filename, label);//存入文件名和对应攻击方式
                loadedFiles.add(filename);//已加载文件存入列表

                byte[] data = resource.getInputStream().readAllBytes();
                parseFile(filename, label, data);//解析文件
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load pcap files", e);
        }
    }

    /**
     * 解析单个文件：对每个包做统计聚合，并采样保留前若干条明细。
     */
    private void parseFile(String filename, String label, byte[] data) {
        final int[] sampled = {0}; // 使用数组包装，便于在 lambda 内累加计数
        PcapNgParser.parse(data, label, packet -> {
            aggregate(packet); // 累加统计
            if (sampled[0] < SAMPLE_LIMIT_PER_FILE) {
                samplePackets.add(packet); // 采样保留明细
                sampled[0]++;
            }
        });
    }

    /**
     * 对单个数据包做统计聚合：总数、字节数、协议分布、大小分桶、异常端口、按 IP 统计。
     */
    private void aggregate(PacketInfo p) {
        totalPackets++;
        totalBytes += p.length();

        // 协议分布
        protocolCount.merge(p.protocol(), 1L, Long::sum);

        // 数据包大小分布
        String bucket = sizeBucket(p.length());
        sizeCount.merge(bucket, 1L, Long::sum);

        // 异常端口流量（源端口或目的端口命中即计数）
        int[] ports = {p.srcPort(), p.dstPort()};
        for (int port : ports) {
            if (isAbnormalPort(port)) {
                portCount.merge(port, 1L, Long::sum);
            }
        }

        // 按 IP 统计（源、目的两个方向都计入；源目的相同时只计一次）
        addIp(p.srcIp(), p.length());
        if (!p.srcIp().equals(p.dstIp())) {
            addIp(p.dstIp(), p.length());
        }
    }

    /** 累加某个 IP 的数据包数与字节数；忽略无效 IP（如 IPv6 占位符 "-"）。 */
    private void addIp(String ip, int bytes) {
        if (ip == null || ip.isEmpty() || ip.equals("-")) {
            return;
        }
        IpStat stat = ipStats.computeIfAbsent(ip, k -> new IpStat());
        stat.packets++;
        stat.bytes += bytes;
    }

    /** 组装返回给前端的统计结果 JSON 结构。 */
    private Map<String, Object> buildStatsResponse() {
        uniqueIpCount = ipStats.size();

        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put("totalPackets", totalPackets);
        overview.put("totalBytes", totalBytes);
        overview.put("uniqueIpCount", uniqueIpCount);
        overview.put("files", new ArrayList<>(loadedFiles));
        overview.put("attackLabels", new LinkedHashMap<>(attackLabels));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("overview", overview);
        response.put("protocol", mapToList(protocolCount));
        response.put("size", sizeCountToList());
        response.put("port", portCountToList());
        response.put("ip", topIpList());
        return response;
    }

    /** 把 Map&lt;String, Long&gt; 转成 [{name, count}] 列表。 */
    private static List<Map<String, Object>> mapToList(Map<String, Long> map) {
        List<Map<String, Object>> list = new ArrayList<>();
        map.forEach((k, v) -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", k);
            item.put("count", v);
            list.add(item);
        });
        return list;
    }

    /** 按固定的 SIZE_BUCKETS 顺序生成大小分布列表（无数据的桶补 0）。 */
    private List<Map<String, Object>> sizeCountToList() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (String bucket : SIZE_BUCKETS) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("range", bucket);
            item.put("count", sizeCount.getOrDefault(bucket, 0L));
            list.add(item);
        }
        return list;
    }

    /** 按固定的 ABNORMAL_PORTS 顺序生成端口统计列表（无数据的端口补 0）。 */
    private List<Map<String, Object>> portCountToList() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (int port : ABNORMAL_PORTS) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("port", port);
            item.put("count", portCount.getOrDefault(port, 0L));
            list.add(item);
        }
        return list;
    }

    /** 取数据包数最多的前 TOP_IP_LIMIT 个 IP。 */
    private List<Map<String, Object>> topIpList() {
        List<Map.Entry<String, IpStat>> entries = new ArrayList<>(ipStats.entrySet());
        entries.sort((a, b) -> Long.compare(b.getValue().packets, a.getValue().packets));

        List<Map<String, Object>> list = new ArrayList<>();
        for (int i = 0; i < Math.min(TOP_IP_LIMIT, entries.size()); i++) {
            Map.Entry<String, IpStat> e = entries.get(i);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ip", e.getKey());
            item.put("packets", e.getValue().packets);
            item.put("bytes", e.getValue().bytes);
            list.add(item);
        }
        return list;
    }

    /** 根据帧长度返回所属的大小分桶区间。 */
    private static String sizeBucket(int length) {
        if (length <= 64) {
            return "<=64";
        } else if (length <= 127) {
            return "65-127";
        } else if (length <= 255) {
            return "128-255";
        } else if (length <= 511) {
            return "256-511";
        } else if (length <= 1023) {
            return "512-1023";
        } else if (length <= 1517) {
            return "1024-1517";
        } else {
            return ">=1518";
        }
    }

    /** 判断端口是否为需要监控的异常端口。 */
    private static boolean isAbnormalPort(int port) {
        for (int p : ABNORMAL_PORTS) {
            if (port == p) {
                return true;
            }
        }
        return false;
    }

    /** 根据抓包文件名推断攻击类型标签。 */
    private static String attackLabelFor(String filename) {
        String lower = filename.toLowerCase();
        if (lower.contains("syn")) {
            return "SYN Flood";
        } else if (lower.contains("icmp")) {
            return "ICMP Flood";
        } else if (lower.contains("arp")) {
            return "ARP Spoof";
        }
        return filename;
    }
}
