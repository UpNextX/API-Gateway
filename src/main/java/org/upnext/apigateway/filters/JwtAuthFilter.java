package org.upnext.apigateway.filters;


import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.upnext.apigateway.utils.JwtUtils;
import org.upnext.sharedlibrary.Dtos.UserDto;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory implements  Ordered {
    private final JwtUtils jwtUtils;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    JwtAuthFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }


    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String token = jwtUtils.getJwtFromHeader(exchange);
            if (token == null || !jwtUtils.isValidToken(token)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            try{
                Claims claims =  jwtUtils.extractAllClaims(token);
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
            }catch (Exception e){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

        };
    }

    @Override
    public int getOrder() {
        return -1;
    }


}