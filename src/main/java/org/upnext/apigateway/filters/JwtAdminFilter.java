package org.upnext.apigateway.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.upnext.sharedlibrary.Dtos.UserDto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Component
public class JwtAdminFilter extends AbstractGatewayFilterFactory {
    private final ObjectMapper objectMapper;

    public JwtAdminFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String token = exchange.getRequest().getHeaders().getFirst("X-User");
            if (token == null) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
            try {

                String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
                UserDto user = null;
                user = objectMapper.readValue(decoded, UserDto.class);

                List<String> roles = user.getRole();
                if (roles == null || !roles.contains("ADMIN")) {
                    return exchange.getResponse().setComplete();

                }
                return chain.filter(exchange);
            } catch(Exception e){
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

        };
    }
}
