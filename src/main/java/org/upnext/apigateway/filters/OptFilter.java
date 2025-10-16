package org.upnext.apigateway.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.upnext.apigateway.utils.JwtUtils;
import org.upnext.sharedlibrary.Dtos.UserDto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Component
@Slf4j
public class OptFilter extends AbstractGatewayFilterFactory<Object> {
    private final JwtUtils jwtUtils;
    Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    OptFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public GatewayFilter apply(Object config) {
        logger.info("Optional Filter ");
        return (exchange, chain) -> {
            String token = jwtUtils.getJwtFromHeader(exchange);
            if (token == null || !jwtUtils.isValidToken(token)) {
                return chain.filter(exchange);
            }
            try {
                Claims claims = jwtUtils.extractAllClaims(token);
                UserDto user = jwtUtils.getUserDto(claims);

                System.out.println(token);
                System.out.println(user);
                ObjectMapper objectMapper = new ObjectMapper();

                String userJson = objectMapper.writeValueAsString(user);

                String encoded = Base64.getEncoder()
                        .encodeToString(userJson.getBytes(StandardCharsets.UTF_8));

                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-User", encoded)
                        .build();
                System.out.println(encoded);
                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            } catch (Exception e) {
                return chain.filter(exchange);
            }

        };
    }

}
