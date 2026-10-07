package com.mamba;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 应用启动类。
 *
 * <p>@SpringBootApplication 是组合注解，等价于同时标注：
 * @Configuration（配置类）、@EnableAutoConfiguration（自动装配）、
 * @ComponentScan（扫描同包及子包下的组件）。
 */
@SpringBootApplication
public class ShengchanshixiApplication {

    /**
     * 程序入口，启动内嵌 Tomcat 并监听配置的端口（application.properties 中为 8081）。
     */
    public static void main(String[] args) {
        SpringApplication.run(ShengchanshixiApplication.class, args);
    }
}
