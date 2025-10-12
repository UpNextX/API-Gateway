package org.upnext.apigateway.filters;


import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
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
public class JwtAuthFilter implements GlobalFilter, Ordered {
    private final JwtUtils jwtUtils;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    JwtAuthFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    private final List<String> publicPaths = List.of("/products/**", "/categories/**", "/auth/**");


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("Filtering JwtAuthFilter");
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod().toString();

        // handle pages that does not need auth
        if(isPublicPath(path) && method.equalsIgnoreCase("GET")){
            return chain.filter(exchange);
        }
        String header  = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (header == null || !header.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try{
            Claims claims =  jwtUtils.extractClaims(header);
            String role = (String) claims.get("role");
            if(path.startsWith("/products") &&
                    !method.equalsIgnoreCase("GET")&&
                    !role.equalsIgnoreCase("ADMIN")){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            UserDto user = new UserDto(
                    ((Number) claims.get("id")).longValue(),
                    (String) claims.get("email"),
                    (String) claims.get("phoneNumber"),
                    (String) claims.get("address"),
                    (String) claims.get("role")
            );
            String userJson = objectMapper.writeValueAsString(user);
            String encoded = Base64.getEncoder()
                    .encodeToString(userJson.getBytes(StandardCharsets.UTF_8));
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User", encoded)
                    .build();
            System.out.println(mutatedRequest.getHeaders().get("X-User"));

            System.out.println(userJson);
            System.out.println(user.toString());

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }catch (Exception e){
            System.out.println("Exception");
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