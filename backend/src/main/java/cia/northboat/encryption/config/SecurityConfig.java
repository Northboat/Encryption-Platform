package cia.northboat.encryption.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/logout").permitAll() // 放行默认登录、登出页面
                        .anyRequest().authenticated()                     // 拦截其他所有请求
                )
                .formLogin()  // 使用默认登录页
                .and()
                .logout()     // 使用默认登出功能
                .and()
                .csrf().disable(); // 若前端是表单测试建议暂时关闭 CSRF（可根据需要打开）

        return http.build();
    }
}