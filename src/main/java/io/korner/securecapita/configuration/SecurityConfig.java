package io.korner.securecapita.configuration;

import io.korner.securecapita.filter.CustomAuthorizationFilter;
import io.korner.securecapita.handler.CustomAccessDeniedHandler;
import io.korner.securecapita.handler.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] PUBLIC_URLS = {"/user/register/**", "/user/login/**", "/user/verify/code/**", "/user/reset-password/**"};
    private final BCryptPasswordEncoder encoder;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final UserDetailsService userDetailsService;
    private final CustomAuthorizationFilter customAuthorizationFilter;

    // Secure the application
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeHttpRequests().requestMatchers(PUBLIC_URLS).permitAll();
        http.authorizeHttpRequests()
                .requestMatchers(HttpMethod.DELETE, "/user/delete/**")
                .hasAnyAuthority("DELETE:USER");
        http.authorizeHttpRequests()
                .requestMatchers(HttpMethod.DELETE, "/customer/delete/**")
                .hasAnyAuthority("DELETE:CUSTOMER");
        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler).authenticationEntryPoint(authenticationEntryPoint);
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    /*
    version < 3.00
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers(PUBLIC_URLS).permitAll();
        http.authorizeRequests()
                .antMatchers(HttpMethod.DELETE, "/user/delete/**")
                .hasAnyAuthority("DELETE:USER");
        http.authorizeRequests()
                .antMatchers(HttpMethod.DELETE, "/customer/delete/**")
                .hasAnyAuthority("DELETE:CUSTOMER");
        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler).authenticationEntryPoint(authenticationEntryPoint);
        http.authorizeRequests().anyRequest().authenticated();
        return http.build();
    }*/

    // Manage the authentication
    @Bean
    public AuthenticationManager authenticationManager(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(encoder);
        return new ProviderManager(authProvider);
    }
}
