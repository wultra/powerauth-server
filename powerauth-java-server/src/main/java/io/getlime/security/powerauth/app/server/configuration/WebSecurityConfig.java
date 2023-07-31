/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.getlime.security.powerauth.app.server.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Class that implements configuration of the Spring Security for RESTful interface
 * of the PowerAuth Server.
 * <p>
 * If a configuration "powerauth.service.restrictAccess" suggests that access should be
 * restricted, HTTP Basic Authentication is used for RESTful API endpoints. Username and
 * passwords can be set in the "pa_integration" table.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig {

    private final PowerAuthServiceConfiguration configuration;
    private final ObjectMapper objectMapper;

    /**
     * Configuration constructor.
     * @param configuration PowerAuth service configuration.
     * @param objectMapper Object mapper.
     */
    public WebSecurityConfig(PowerAuthServiceConfiguration configuration, ObjectMapper objectMapper) {
        this.configuration = configuration;
        this.objectMapper = objectMapper;
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        if (configuration.getRestrictAccess()) {
            logger.info("Initializing basic http authentication");
            return http
                    .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new AntPathRequestMatcher("/rest/**"))
                            .authenticated()
                        .requestMatchers(new AntPathRequestMatcher("/actuator/**"), new AntPathRequestMatcher("/swagger-resources/**"))
                            .permitAll()
                        .anyRequest()
                            .permitAll())
                    .httpBasic(httpBasic -> httpBasic.authenticationEntryPoint(authenticationEntryPoint()))
                    .csrf(AbstractHttpConfigurer::disable)
                    .build();
        } else {
            logger.info("No http authentication used");
            return http
                    .httpBasic().disable()
                    .csrf(AbstractHttpConfigurer::disable)
                    .build();
        }
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (httpServletRequest, httpServletResponse, e) -> {
            final ErrorResponse errorResponse = new ErrorResponse("ERR_AUTHENTICATION", "Authentication failed");
            httpServletResponse.setContentType("application/json");
            httpServletResponse.setCharacterEncoding("UTF-8");
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpServletResponse.getOutputStream().println(objectMapper.writeValueAsString(errorResponse));
            httpServletResponse.getOutputStream().flush();
        };
    }

    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        // API client token and secret are stored in plain text so that they can be displayed in PowerAuth Admin
        logger.info("Initializing NoOpPasswordEncoder");
        return NoOpPasswordEncoder.getInstance();
    }
}
