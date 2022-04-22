package com.example.jwt.properties;

public interface JwtProperties {
    String SECRET = "jby";
    Integer EXPIRATION_TIME = 1000 * 60 * 30;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
