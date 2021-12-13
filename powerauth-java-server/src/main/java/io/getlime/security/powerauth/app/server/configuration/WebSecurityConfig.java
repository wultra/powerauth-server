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
import io.getlime.security.powerauth.app.server.integration.IntegrationUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletResponse;

/**
 * Class that implements configuration of the Spring Security for RESTful interface
 * of the PowerAuth Server. This configuration is prepared in such a way that it
 * does not apply to the SOAP interface - only to REST.
 *
 * If a configuration "powerauth.service.restrictAccess" suggests that access should be
 * restricted, HTTP Basic Authentication is used for RESTful API endpoints. Username and
 * passwords can be set in the "pa_integration" table.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final IntegrationUserDetailsService userDetailsService;
    private final PowerAuthServiceConfiguration configuration;
    private final ObjectMapper objectMapper;

    /**
     * Configuration constructor.
     * @param userDetailsService User details service.
     * @param configuration PowerAuth service configuration.
     * @param objectMapper Object mapper.
     */
    public WebSecurityConfig(IntegrationUserDetailsService userDetailsService, PowerAuthServiceConfiguration configuration, ObjectMapper objectMapper) {
        this.userDetailsService = userDetailsService;
        this.configuration = configuration;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (configuration.getRestrictAccess()) {
            http
                    .authorizeRequests()
                    .antMatchers("/rest/**").authenticated()
                    .antMatchers("/actuator/**", "/swagger-resources/**").permitAll()
                    .anyRequest().permitAll()
                    .and()
                    .httpBasic()
                    .authenticationEntryPoint(authenticationEntryPoint())
                    .and()
                    .csrf().disable();
        } else {
            http
                    .httpBasic().disable()
                    .csrf().disable();
        }
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (httpServletRequest, httpServletResponse, e) -> {
            ErrorResponse errorResponse = new ErrorResponse("ERR_AUTHENTICATION", "Authentication failed");
            httpServletResponse.setContentType("application/json");
            httpServletResponse.setCharacterEncoding("UTF-8");
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpServletResponse.getOutputStream().println(objectMapper.writeValueAsString(errorResponse));
            httpServletResponse.getOutputStream().flush();
        };
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // API client token and secret are stored in plain text so that they can be displayed in PowerAuth Admin
        auth.userDetailsService(userDetailsService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return userDetailsService;
    }
}
