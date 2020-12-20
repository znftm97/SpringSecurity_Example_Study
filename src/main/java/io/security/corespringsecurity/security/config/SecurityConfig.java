package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.handler.CustomAutheticationFailureHandler;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;

    // 인증 성공시 핸들러
    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    // 인증 실패시 핸들러
    @Autowired
    private CustomAutheticationFailureHandler autheticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /*@Autowired
    private UserDetailsService userDetailsService;*/

    @Bean
        public AuthenticationProvider authenticationProvider(){
            return new CustomAuthenticationProvider(passwordEncoder());
    }

    //인가 처리 핸들러
    @Bean
    public CustomAccessDeniedHandler accessDeniedHandler(){
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");

        return accessDeniedHandler;
    }

    //인증
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*auth.userDetailsService(userDetailsService);*/ //UserDetailsService
        auth.authenticationProvider(authenticationProvider()); //AuthenticationProvider
    }

    //정적 파일들 보안필터 적용x
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users", "user/login/**", "/login*").permitAll() // 해당 경로에 누구나 접근 가능
                .antMatchers("/mypage").hasRole("USER") // 해당 경로에 USER만 접근 가능
                .antMatchers("/messages").hasRole("MANAGER") // 해당 경로에 MANAGER만 접근 가능
                .antMatchers("/config").hasRole("ADMIN") // 해당 경로에 ADMIN만 접근 가능
                .anyRequest().authenticated()
        .and()
                .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/login_proc")
                    .authenticationDetailsSource(authenticationDetailsSource)
                    .defaultSuccessUrl("/")
                    .successHandler(authenticationSuccessHandler)
                    .failureHandler(autheticationFailureHandler)
                    .permitAll();
        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        ;
    }


}
