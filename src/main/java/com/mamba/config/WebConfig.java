package com.mamba.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web 配置：开启跨域（CORS）。
 *
 * <p>前端使用 Vite 开发服务器（端口 5173）独立运行，通过代理访问后端；
 * 这里放开 CORS，使得前端也能直接跨域请求后端接口（端口 8081）。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * 为 /api/** 接口配置跨域规则。
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")               // 匹配所有 API 接口
                .allowedOriginPatterns("*")          // 允许任意来源
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // 允许的 HTTP 方法
                .allowedHeaders("*")                 // 允许任意请求头
                .maxAge(3600);                       // 预检请求缓存 1 小时
    }
}
