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

package io.getlime.security.app.admin.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * LDAP Configuration
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
public class LdapConfiguration {

    @Value("${powerauth.admin.security.ldap.userDNPatterns}")
    private String ldapUserDNPatterns;

    @Value("${powerauth.admin.security.ldap.userSearchBase}")
    private String ldapUserSearchBase;

    @Value("${powerauth.admin.security.ldap.userSearchFilter}")
    private String ldapUserSearchFilter;

    @Value("${powerauth.admin.security.ldap.groupSearchBase}")
    private String ldapGroupSearchBase;

    @Value("${powerauth.admin.security.ldap.groupSearchFilter}")
    private String ldapGroupSearchFilter;

    @Value("${powerauth.admin.security.ldap.groupRoleAttribute}")
    private String ldapGroupRoleAttribute;

    @Value("${powerauth.admin.security.ldap.ldif}")
    private String ldapLdif;

    @Value("${powerauth.admin.security.ldap.url}")
    private String ldapUrl;

    @Value("${powerauth.admin.security.ldap.port}")
    private String ldapPort;

    @Value("${powerauth.admin.security.ldap.root}")
    private String ldapRoot;

    @Value("${powerauth.admin.security.ldap.managerDN}")
    private String ldapManagerDN;

    @Value("${powerauth.admin.security.ldap.managerPassword}")
    private String ldapManagerPassword;

    public String getLdapUserDNPatterns() {
        return ldapUserDNPatterns;
    }

    public void setLdapUserDNPatterns(String ldapUserDNPatterns) {
        this.ldapUserDNPatterns = ldapUserDNPatterns;
    }

    public String getLdapUserSearchBase() {
        return ldapUserSearchBase;
    }

    public void setLdapUserSearchBase(String ldapUserSearchBase) {
        this.ldapUserSearchBase = ldapUserSearchBase;
    }

    public String getLdapUserSearchFilter() {
        return ldapUserSearchFilter;
    }

    public void setLdapUserSearchFilter(String ldapUserSearchFilter) {
        this.ldapUserSearchFilter = ldapUserSearchFilter;
    }

    public String getLdapGroupSearchBase() {
        return ldapGroupSearchBase;
    }

    public void setLdapGroupSearchBase(String ldapGroupSearchBase) {
        this.ldapGroupSearchBase = ldapGroupSearchBase;
    }

    public String getLdapGroupSearchFilter() {
        return ldapGroupSearchFilter;
    }

    public void setLdapGroupSearchFilter(String ldapGroupSearchFilter) {
        this.ldapGroupSearchFilter = ldapGroupSearchFilter;
    }

    public String getLdapGroupRoleAttribute() {
        return ldapGroupRoleAttribute;
    }

    public void setLdapGroupRoleAttribute(String ldapGroupRoleAttribute) {
        this.ldapGroupRoleAttribute = ldapGroupRoleAttribute;
    }

    public String getLdapLdif() {
        return ldapLdif;
    }

    public void setLdapLdif(String ldapLdif) {
        this.ldapLdif = ldapLdif;
    }

    public String getLdapUrl() {
        return ldapUrl;
    }

    public void setLdapUrl(String ldapUrl) {
        this.ldapUrl = ldapUrl;
    }

    public String getLdapPort() {
        return ldapPort;
    }

    public void setLdapPort(String ldapPort) {
        this.ldapPort = ldapPort;
    }

    public String getLdapRoot() {
        return ldapRoot;
    }

    public void setLdapRoot(String ldapRoot) {
        this.ldapRoot = ldapRoot;
    }

    public String getLdapManagerDN() {
        return ldapManagerDN;
    }

    public void setLdapManagerDN(String ldapManagerDN) {
        this.ldapManagerDN = ldapManagerDN;
    }

    public String getLdapManagerPassword() {
        return ldapManagerPassword;
    }

    public void setLdapManagerPassword(String ldapManagerPassword) {
        this.ldapManagerPassword = ldapManagerPassword;
    }

}
