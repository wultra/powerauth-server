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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Spring Security configuration class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final ApplicationConfiguration configuration;
    private final LdapConfiguration ldapConfiguration;
    private final ActiveDirectoryConfiguration activeDirectoryConfiguration;

    @Autowired
    public WebSecurityConfig(ApplicationConfiguration configuration, LdapConfiguration ldapConfiguration, ActiveDirectoryConfiguration activeDirectoryConfiguration) {
        this.configuration = configuration;
        this.ldapConfiguration = ldapConfiguration;
        this.activeDirectoryConfiguration = activeDirectoryConfiguration;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (!configuration.getSecurityMethod().isEmpty()) {
            http.authorizeRequests()
                    .antMatchers("/resources/**", "/api/service/**", "/actuator/**").permitAll()
                    .anyRequest().fullyAuthenticated()
                    .and()
                    .formLogin().loginPage("/login").permitAll()
                    .and()
                    .logout().permitAll();
            http.httpBasic()
                    .disable();
        }
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        final String securityMethod = configuration.getSecurityMethod();
        if (SecurityUtil.isLdap(securityMethod)) {
            SecurityUtil.configureLdap(auth, ldapConfiguration);
        } else if (SecurityUtil.isActiveDirectory(securityMethod)) {
            SecurityUtil.configureActiveDirectory(auth, activeDirectoryConfiguration);
        }
    }

}
