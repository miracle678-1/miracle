package com.mamba.controller;

import com.mamba.service.TrafficAnalysisService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 流量分析 REST 接口层。
 *
 * <p>只负责接收 HTTP 请求、校验参数并调用 Service，不包含业务逻辑。
 * 所有接口统一挂在 /api 前缀下，返回 JSON 数据给前端。
 */
@RestController
@RequestMapping("/api")
public class TrafficController {

    /** 注入的流量分析服务。 */
    private final TrafficAnalysisService service;

    /** 通过构造器注入（Spring 推荐做法）。 */
    public TrafficController(TrafficAnalysisService service) {
        this.service = service;
    }

    /**
     * 获取全部统计结果（概览 + 协议分布 + 大小分布 + 端口统计 + IP 统计），供图表使用。
     */
    @GetMapping("/stats")
    //获取图表信息
    public Map<String, Object> stats() {
        return service.getStats();
    }

    /**
     * 分页获取五元组明细列表，供表格展示。
     *
     * @param page 页码（从 0 开始，默认 0）
     * @param size 每页条数（默认 20，限制在 1~100 之间）
     */
    @GetMapping("/packets")
    //获取五元组明细结果信息
    public Map<String, Object> packets(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        int safeSize = Math.max(1, Math.min(size, 100)); // size 钳制在 1~100，防止一次拉取过多
        int safePage = Math.max(0, page);                // page 不能为负数
        return service.getPackets(safePage, safeSize);
    }

    /**
     * 强制重新解析 pcap 文件并刷新统计缓存（替换抓包文件后调用）。
     */
    @GetMapping("/reload")
    //强行重新解析
    public Map<String, Object> reload() {
        return service.reload();
    }
}
