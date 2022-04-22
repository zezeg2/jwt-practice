package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.user.User;
import com.example.jwt.model.user.UserRepository;
import com.example.jwt.properties.JwtProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.example.jwt.properties.JwtProperties.*;

/*
 시큐리티 필터중 BasicAuthenticationFilter 라는 것이 있음
 권한이나 인증이 필요한 특정 주소를 요청했을 때 이 필터를 타게 되어있음
 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 타지 않음
 */


public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    /* 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨. */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소가 요청이 됨 ");
        String jwtHeader = request.getHeader(HEADER_STRING);
        System.out.println("jwtHeader : " + jwtHeader);

        /* JWT 토큰을 검증을 해서 정상적인 사용자인지 확인 */
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request,response);
            return;
        }
        String jwtToken = request.getHeader(HEADER_STRING).replace(TOKEN_PREFIX,"");
        String username = JWT.require(Algorithm.HMAC512(SECRET)).build().verify(jwtToken).getClaim("username").asString();


        /* 서명이 정상적으로 되었을 때 */
        if (username != null){
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetail = new PrincipalDetails(userEntity);

            /* JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다 */
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetail, null, principalDetail.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }
    }
}