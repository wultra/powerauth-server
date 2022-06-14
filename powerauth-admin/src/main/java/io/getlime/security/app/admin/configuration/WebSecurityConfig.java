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

import io.getlime.security.app.admin.security.SecurityMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
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

    @Autowired
    public WebSecurityConfig(ApplicationConfiguration configuration) {
        this.configuration = configuration;
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

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (SecurityMethod.isLdap(configuration.getSecurityMethod())) {

            LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthentication = auth.ldapAuthentication();
            if (!configuration.getLdapGroupRoleAttribute().isEmpty()) {
                ldapAuthentication = ldapAuthentication.groupRoleAttribute(configuration.getLdapGroupRoleAttribute());
            }
            if (!configuration.getLdapGroupSearchBase().isEmpty()) {
                ldapAuthentication = ldapAuthentication.groupSearchBase(configuration.getLdapGroupSearchBase());
            }
            if (!configuration.getLdapGroupSearchFilter().isEmpty()) {
                ldapAuthentication = ldapAuthentication.groupSearchFilter(configuration.getLdapGroupSearchFilter());
            }
            if (!configuration.getLdapUserDNPatterns().isEmpty()) {
                ldapAuthentication = ldapAuthentication.userDnPatterns(configuration.getLdapUserDNPatterns());
            }
            if (!configuration.getLdapUserSearchBase().isEmpty()) {
                ldapAuthentication = ldapAuthentication.userSearchBase(configuration.getLdapUserSearchBase());
            }
            if (!configuration.getLdapUserSearchFilter().isEmpty()) {
                ldapAuthentication = ldapAuthentication.userSearchFilter(configuration.getLdapUserSearchFilter());
            }

            LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder>.ContextSourceBuilder contextSource = ldapAuthentication.contextSource();
            if (!configuration.getLdapUrl().isEmpty()) {
                contextSource.url(configuration.getLdapUrl());
            }
            if (!configuration.getLdapPort().isEmpty()) {
                contextSource.port(Integer.parseInt(configuration.getLdapPort()));
            }
            if (!configuration.getLdapRoot().isEmpty()) {
                contextSource.root(configuration.getLdapRoot());
            }
            if (!configuration.getLdapLdif().isEmpty()) {
                contextSource.ldif(configuration.getLdapLdif());
            }
            if (!configuration.getLdapManagerDN().isEmpty()) {
                contextSource.managerDn(configuration.getLdapManagerDN());
            }
            if (!configuration.getLdapManagerPassword().isEmpty()) {
                contextSource.managerPassword(configuration.getLdapManagerPassword());
            }
        }
    }

}
