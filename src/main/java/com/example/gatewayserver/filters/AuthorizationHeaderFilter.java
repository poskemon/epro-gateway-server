package com.example.gatewayserver.filters;

import io.jsonwebtoken.Claims;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;

import org.springframework.stereotype.Component;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CustomFilter
 * 토큰 확인 필터
 */
@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private final JwtValidation jwtValidation;

    public AuthorizationHeaderFilter(JwtValidation jwtValidation) {
        super(Config.class);
        this.jwtValidation = jwtValidation;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest(); // Pre Filter
            ServerHttpResponse response = exchange.getResponse(); // Post Filter
            log.info("AuthorizationHeaderFilter Pre filter: request id -> {}", request.getId());

            // Request Header 에 token 이 존재하지 않는 경우
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Not found authorization header!", HttpStatus.UNAUTHORIZED); // 401 Error
            }

            try {
                // 토큰 유효성 확인
                String authorization = Objects.requireNonNull(request.getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
                String token = authorization.replace("Bearer", "").trim();

                Claims userInfo = jwtValidation.validateAndGetUserInfo(token);
                log.info("Authenticated user info : " + userInfo.toString());

                return chain.filter(exchange);
            } catch (Exception e) {
                return onError(exchange, "Token is not valid.", HttpStatus.UNAUTHORIZED); // 401 Error
            }
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String e, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse(); // Post Filter

        response.setStatusCode(httpStatus);
        log.info("AuthorizationHeaderFilter Post filter: response code -> {}", response.getStatusCode());

        return response.setComplete();
    }

    public static class Config {

    }
}