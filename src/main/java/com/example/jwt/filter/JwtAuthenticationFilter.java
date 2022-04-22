package com.example.jwt.filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.properties.JwtProperties;
import com.example.jwt.model.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

import static com.example.jwt.properties.JwtProperties.*;

/*
  스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
  /login 요청에서 username, password 전송하면(post)
  UsernamePasswordAuthenticationFilter 동작
 */

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    /* login 요청을 하면 로그인 시도를 위해서 실행되는 함수 */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("-----------------------  JwtAuthenticationFilter  -----------------------");

        /*
         1. ObjectManager를 통해 username, password 받아서
         2. UsernamePasswordAuthenticationToken를 통해 토큰을 생성
         3. AuthenticationManager(interface)에 UsernamePasswordAuthenticationToken를 입력하여 인증 프로세스 진행(ProviderManager)(구현체)
         4. PrincipalDetailService 가 호출 됨, loadUserByUsername 메서드 실행하여 유저 세부정보 리턴(-> AuthenticationProvider)
         5. 인증과정이 정상실행 되면 (DB에 있는 username, password 가 일치한다) authentication 객체 리턴
         6. PrincipalDetail을 세션에 담고(선택, 권한 관리를 위해서)
         7. JWT 토큰을 만들어서 응답해주면됨
        */

        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("Input Value : {} ", user);

            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principalDetail = (PrincipalDetails) authentication.getPrincipal();
            log.info("Login successful : {}", principalDetail.getUser().getUsername());

            /*

            */
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }


    /*
    attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 메서드 실행
    JWT 토큰을 만들어서 request 한 사용자에게 JWT 토큰을 response 해준다.
    */

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetail = (PrincipalDetails) authResult.getPrincipal();

        /* Hash 암호방식 */
        String jwtToken = JWT.create()
                .withSubject(principalDetail.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .withClaim("id", principalDetail.getUser().getId())
                .withClaim("username", principalDetail.getUser().getUsername())
                .sign(Algorithm.HMAC512(SECRET));
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + jwtToken);
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
