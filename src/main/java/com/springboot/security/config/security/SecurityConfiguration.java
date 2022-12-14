package com.springboot.security.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 어플리케이션의 보안 설정
 * 예제 13.19
 *
 * @author Flature
 * @version 1.0.0
 */
@Configuration
//@EnableWebSecurity // Spring Security에 대한 디버깅 모드를 사용하기 위한 어노테이션 (default : false)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public SecurityConfiguration(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic().disable() // REST API는 UI를 사용하지 않으므로 기본설정을 비활성화

             // ! 크로스 브라우저
            // REST API는 csrf 보안이 필요 없으므로 비활성화
            .csrf().disable()

             // ! 세션
            .sessionManagement()
            // JWT Token 인증방식으로 세션은 필요 없으므로 비활성화
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            // ! 요청
            .and()
            // 리퀘스트에 대한 사용권한 체크
            .authorizeRequests()

            // 가입 및 로그인 주소는 허용
            .antMatchers("/sign-api/sign-in", "/sign-api/sign-up","/sign-api/exception").permitAll()

            // product로 시작하는 Get 요청은 허용
            .antMatchers(HttpMethod.GET, "/product/**").permitAll()

            .antMatchers("**exception**").permitAll()

            // 나머지 요청은 인증된 ADMIN만 접근 가능
            .anyRequest().hasRole("ADMIN")

            // ! 권한 및 예외
            .and()
            // 권한을 확인하는 과정에서 통과하지 못하는 예외가 발생하는 경우 예외를 전달한다
            .exceptionHandling().accessDeniedHandler(new CustomAccessDeniedHandler())


            .and()
            // 인증 과정에서 예외가 발생할 경우 예외를 전달한다
            .exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())

            // ! 필터
            .and()
            // JWT Token 필터를 id/password 인증 필터 이전에 추가
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),UsernamePasswordAuthenticationFilter.class);

    }

    /**
     * Swagger 페이지 접근에 대한 예외 처리
     *
     * @param webSecurity
     */
    @Override
    public void configure(WebSecurity webSecurity) {
        webSecurity.ignoring().antMatchers("/v2/api-docs", "/swagger-resources/**",
            "/swagger-ui.html", "/webjars/**", "/swagger/**", "/sign-api/exception");
    }
}