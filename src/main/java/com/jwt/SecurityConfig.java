package com.jwt;

import com.jwt.Jwt.AuthEntryPointJwt;
import com.jwt.Jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
@Configuration //This tell configuring class to generate one or more beans
@EnableWebSecurity //Enabling spring security
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private DataSource dataSource;  //Based on pom.xml & application.properties spring automatically gives Datasource bean

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated());
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS)
        );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        //http.httpBasic(withDefaults());
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                )
        );
        http.csrf(csrf -> csrf.disable());
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

//    @Bean //created Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//            .authorizeHttpRequests((requests) ->
//             requests.requestMatchers("/h2-console/**").permitAll()
//            .anyRequest().authenticated())
//            .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//           //http.formLogin(withDefaults());
//            .httpBasic(withDefaults())
//           //http.headers(headers ->headers.frameOptions(frameOptions(frameOptions -> frameOptions.sa)));
//            .headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
//            .csrf(AbstractHttpConfigurer::disable);
//        return http.build();
//    }

    @Bean
    public UserDetailsService userDetailsService (DataSource dataSource ){
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user = User.withUsername("digvijay")
                    //.password("{noop}1234")  //If we do not want to encode password use {noop}
                    .password(passwordEncoder().encode("1234")) //Password is encoded
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    //.password("{noop}1234")
                    .password(passwordEncoder().encode("1234"))
                    .roles("ADMIN")
                    .build();
            JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(user);
            jdbcUserDetailsManager.createUser(admin);//Users are saved in database
        } ;
    }


//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user= User.withUsername("digvijay")
//                //.password("{noop}1234")  //If we do not want to encode password use {noop}
//                .password(passwordEncoder().encode("1234")) //Password is encoded
//                .roles("USER")
//                .build();
//
//        UserDetails admin=User.withUsername("admin")
//                //.password("{noop}1234")
//                .password(passwordEncoder().encode("1234"))
//                .roles("ADMIN")
//                .build();
//        JdbcUserDetailsManager  jdbcUserDetailsManager=new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.createUser(user);
//        jdbcUserDetailsManager.createUser(admin);//Users are saved in database
//        return jdbcUserDetailsManager;
//        //return new InMemoryUserDetailsManager(user,admin); //User will be saved in  memory not in database
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
//Hashing means ,Hashing is a one-way mathematical function that turns data into a Encoded string
//Salting means ,Adding encoded string into Hashing to secure password more effectively