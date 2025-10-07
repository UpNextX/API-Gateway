package org.upnext.apigateway.configs;

import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "security")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityPaths {
    List<RouteRule> publicRoutes;
    List<RouteRule> adminRoutes;
    List<RouteRule> userRoutes;

    @PostConstruct
    public void init() {
        System.out.println("Public Rules: " + publicRoutes);
        System.out.println("Admin Rules: " + adminRoutes);
        System.out.println("Users Rules: " + userRoutes);
    }
}
