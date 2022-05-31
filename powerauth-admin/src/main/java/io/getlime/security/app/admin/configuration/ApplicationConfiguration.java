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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * The main application configuration object.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@ConfigurationProperties("ext")
@ComponentScan(basePackages = {"io.getlime.security.powerauth"})
public class ApplicationConfiguration {

    @Value("${powerauth.service.url}")
    private String powerAuthServiceUrl;

    @Value("${powerauth.service.security.clientToken}")
    private String clientToken;

    @Value("${powerauth.service.security.clientSecret}")
    private String clientSecret;

    @Value("${powerauth.service.ssl.acceptInvalidSslCertificate}")
    private boolean acceptInvalidSslCertificate;

    @Value("${powerauth.admin.security.method}")
    private String securityMethod;

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

    @Value("${powerauth.admin.service.applicationName}")
    private String applicationName;

    @Value("${powerauth.admin.service.applicationDisplayName}")
    private String applicationDisplayName;

    @Value("${powerauth.admin.service.applicationEnvironment}")
    private String applicationEnvironment;

    // Getters and setters

    public String getPowerAuthServiceUrl() {
        return powerAuthServiceUrl;
    }

    public void setPowerAuthServiceUrl(String powerAuthServiceUrl) {
        this.powerAuthServiceUrl = powerAuthServiceUrl;
    }

    public String getClientToken() {
        return clientToken;
    }

    public void setClientToken(String clientToken) {
        this.clientToken = clientToken;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public boolean isAcceptInvalidSslCertificate() {
        return acceptInvalidSslCertificate;
    }

    public void setAcceptInvalidSslCertificate(boolean acceptInvalidSslCertificate) {
        this.acceptInvalidSslCertificate = acceptInvalidSslCertificate;
    }

    public String getSecurityMethod() {
        return securityMethod;
    }

    public void setSecurityMethod(String securityMethod) {
        this.securityMethod = securityMethod;
    }

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

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getApplicationDisplayName() {
        return applicationDisplayName;
    }

    public void setApplicationDisplayName(String applicationDisplayName) {
        this.applicationDisplayName = applicationDisplayName;
    }

    public String getApplicationEnvironment() {
        return applicationEnvironment;
    }

    public void setApplicationEnvironment(String applicationEnvironment) {
        this.applicationEnvironment = applicationEnvironment;
    }
}
