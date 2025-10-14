package org.upnext.apigateway.filters;


import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
public class JwtAuthFilter implements GlobalFilter, Ordered {
    private final JwtUtils jwtUtils;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    JwtAuthFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    private final List<String> publicPaths = List.of("/products/**", "/categories/**", "/auth/**");


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("Filtering JwtAuthFilter");
        String path = exchange.getRequest().getURI().getPath();

        // handle pages that does not need auth
        if(isPublicPath(path)){
            return chain.filter(exchange);
        }
        String header  = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (header == null || !header.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try{
            jwtUtils.isValidToken(header);
            return chain.filter(exchange);
        }catch (Exception e){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();

        }
    }

    private boolean isPublicPath(String path) {
        return publicPaths.stream().anyMatch(p -> pathMatcher.match(p, path));
    }
    @Override
    public int getOrder() {
        return -1;
    }
}