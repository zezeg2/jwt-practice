package com.example.jwt.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpRes = (HttpServletResponse) response;


        if(httpReq.getMethod().equals("POST")){
            String headerAuth =  httpReq.getHeader("Authorization");
            System.out.println("Filter3");

            if (headerAuth.equals("hello")){
                /** 토큰 : hello, id. pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다
                 * 요청할 때 마다 header에 Authorization 에 value값으로 토큰을 가지고 옴
                 * 그 때 토큰이 넘오오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면됨(RSA, HS256)
                 */
                chain.doFilter(httpReq,httpRes);

            } else{
                PrintWriter out = httpRes.getWriter();
            }
        }
    }
}
