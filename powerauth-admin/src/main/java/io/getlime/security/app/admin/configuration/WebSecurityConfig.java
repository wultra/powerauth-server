/*
 * Copyright 2017 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.app.admin.configuration;

import io.getlime.security.app.admin.util.SecurityUtil;
import jakarta.servlet.DispatcherType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Spring Security configuration class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig {

    private final ApplicationConfiguration configuration;
    private final LdapConfiguration ldapConfiguration;
    private final ActiveDirectoryConfiguration activeDirectoryConfiguration;

    @Autowired
    public WebSecurityConfig(ApplicationConfiguration configuration, LdapConfiguration ldapConfiguration, ActiveDirectoryConfiguration activeDirectoryConfiguration) {
        this.configuration = configuration;
        this.ldapConfiguration = ldapConfiguration;
        this.activeDirectoryConfiguration = activeDirectoryConfiguration;
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        if (!configuration.getSecurityMethod().isEmpty()) {
            logger.info("Initializing HTTP authentication");
            return http
                    .authorizeHttpRequests(authorize -> authorize
                            .dispatcherTypeMatchers(DispatcherType.FORWARD)
                            .permitAll()
                            .requestMatchers(
                                    new AntPathRequestMatcher("/resources/**"),
                                    new AntPathRequestMatcher("/api/service/**"),
                                    new AntPathRequestMatcher("/actuator/**"))
                            .permitAll()
                            .anyRequest()
                            .fullyAuthenticated())
                    .formLogin(formLogin ->
                            formLogin.loginPage("/login")
                                    .permitAll())
                    .logout(LogoutConfigurer::permitAll)
                    .httpBasic(AbstractHttpConfigurer::disable)
                    .build();
        } else {
            logger.info("HTTP authentication is disabled");
            return http.build();
        }
    }

    @Autowired
    public void registerAuthenticationProvider(final AuthenticationManagerBuilder auth) throws Exception {
        final String securityMethod = configuration.getSecurityMethod();
        if (SecurityUtil.isLdap(securityMethod)) {
            logger.info("Initializing ldap authentication provider.");
            SecurityUtil.configureLdap(auth, ldapConfiguration);
        } else if (SecurityUtil.isActiveDirectory(securityMethod)) {
            logger.info("Initializing active-directory authentication provider.");
            SecurityUtil.configureActiveDirectory(auth, activeDirectoryConfiguration);
        }
    }

}
