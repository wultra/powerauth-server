/*
 * PowerAuth Server and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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

package io.getlime.security.app.admin.util;

import io.getlime.security.app.admin.configuration.ActiveDirectoryConfiguration;
import io.getlime.security.app.admin.configuration.LdapConfiguration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.util.StringUtils;

/**
 * Utility class for various security related tasks.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class SecurityUtil {

    /**
     * Authentication via LDAP.
     */
    public static final String LDAP = "ldap";

    /**
     * Authentication via Active Directory.
     */
    public static final String ACTIVE_DIRECTORY = "active-directory";

    /**
     * Checks if a provided security method is LDAP authentication.
     * @param securityMethod Security method to be tested.
     * @return True in case given method represents LDAP authentication, false otherwise.
     */
    public static boolean isLdap(String securityMethod) {
        return securityMethod != null && securityMethod
                .trim()
                .equalsIgnoreCase(LDAP);
    }

    /**
     * Checks if a provided security method is Active Directory authentication.
     * @param securityMethod Security method to be tested.
     * @return True in case given method represents Active Directory authentication, false otherwise.
     */
    public static boolean isActiveDirectory(String securityMethod) {
        return securityMethod != null && securityMethod
                .trim()
                .equalsIgnoreCase(ACTIVE_DIRECTORY);
    }

    public static void configureLdap(AuthenticationManagerBuilder auth, LdapConfiguration configuration) throws Exception {
        final LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthenticationBuilder = auth.ldapAuthentication();
        if (!configuration.getLdapGroupRoleAttribute().isEmpty()) {
            ldapAuthenticationBuilder.groupRoleAttribute(configuration.getLdapGroupRoleAttribute());
        }
        if (!configuration.getLdapGroupSearchBase().isEmpty()) {
            ldapAuthenticationBuilder.groupSearchBase(configuration.getLdapGroupSearchBase());
        }
        if (!configuration.getLdapGroupSearchFilter().isEmpty()) {
            ldapAuthenticationBuilder.groupSearchFilter(configuration.getLdapGroupSearchFilter());
        }
        if (!configuration.getLdapUserDNPatterns().isEmpty()) {
            ldapAuthenticationBuilder.userDnPatterns(configuration.getLdapUserDNPatterns());
        }
        if (!configuration.getLdapUserSearchBase().isEmpty()) {
            ldapAuthenticationBuilder.userSearchBase(configuration.getLdapUserSearchBase());
        }
        if (!configuration.getLdapUserSearchFilter().isEmpty()) {
            ldapAuthenticationBuilder.userSearchFilter(configuration.getLdapUserSearchFilter());
        }

        final LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder>.ContextSourceBuilder contextSource = ldapAuthenticationBuilder.contextSource();
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

    public static void configureActiveDirectory(AuthenticationManagerBuilder auth, ActiveDirectoryConfiguration configuration) {
        final String activeDirectoryDomain = configuration.getActiveDirectoryDomain();
        final String ldapUrl = configuration.getActiveDirectoryUrl();
        final String ldapRoot = configuration.getActiveDirectoryRoot();
        final ActiveDirectoryLdapAuthenticationProvider authenticationProvider = new ActiveDirectoryLdapAuthenticationProvider(activeDirectoryDomain, ldapUrl, ldapRoot);
        final String userSearchFilter = configuration.getActiveDirectoryUserSearchFilter();
        if (StringUtils.hasText(userSearchFilter)) {
            authenticationProvider.setSearchFilter(userSearchFilter);
        }
        auth.authenticationProvider(authenticationProvider);
    }

}
