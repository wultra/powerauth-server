/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.client;

/**
 * Configuration of PowerAuth REST client.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthRestClientConfiguration {

    // Use 1 MB as default maximum memory size
    private int maxMemorySize = 1024 * 1024;
    // Use 5 seconds as default connect timeout
    private int connectTimeout = 5000;
    private boolean proxyEnabled = false;
    private String proxyHost;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;
    private String powerAuthClientToken;
    private String powerAuthClientSecret;
    private boolean acceptInvalidSslCertificate;

    /**
     * Get maximum memory size for HTTP requests in bytes.
     * @return Maximum memory size for HTTP requests in bytes.
     */
    public int getMaxMemorySize() {
        return maxMemorySize;
    }

    /**
     * Set maximum memory size for HTTP requests in bytes.
     * @param maxMemorySize Maximum memory size for HTTP requests in bytes.
     */
    public void setMaxMemorySize(int maxMemorySize) {
        this.maxMemorySize = maxMemorySize;
    }

    /**
     * Get connection timeout in milliseconds.
     * @return Connection timeout in milliseconds.
     */
    public int getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * Set connection timeout in milliseconds.
     * @param connectTimeout Connection timeout in milliseconds.
     */
    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    /**
     * Get whether HTTP proxy is enabled.
     * @return Whether HTTP proxy is enabled.
     */
    public boolean isProxyEnabled() {
        return proxyEnabled;
    }

    /**
     * Set whether HTTP proxy is enabled.
     * @param proxyEnabled Whether HTTP proxy is enabled.
     */
    public void setProxyEnabled(boolean proxyEnabled) {
        this.proxyEnabled = proxyEnabled;
    }

    /**
     * Get proxy host.
     * @return Proxy host.
     */
    public String getProxyHost() {
        return proxyHost;
    }

    /**
     * Set proxy host.
     * @param proxyHost Proxy host.
     */
    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    /**
     * Get proxy port.
     * @return Proxy port.
     */
    public int getProxyPort() {
        return proxyPort;
    }

    /**
     * Set proxy port.
     * @param proxyPort Proxy port.
     */
    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * Get proxy username.
     * @return Proxy username.
     */
    public String getProxyUsername() {
        return proxyUsername;
    }

    /**
     * Set proxy username.
     * @param proxyUsername Proxy username.s
     */
    public void setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }

    /**
     * Get proxy password.
     * @return Proxy password.
     */
    public String getProxyPassword() {
        return proxyPassword;
    }

    /**
     * Set proxy password.
     * @param proxyPassword Proxy password.
     */
    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    /**
     * Get HTTP basic authentication username.
     * @return HTTP basic authentication username.
     */
    public String getPowerAuthClientToken() {
        return powerAuthClientToken;
    }

    /**
     * Set HTTP basic authentication username.
     * @param powerAuthClientToken HTTP basic authentication username.
     */
    public void setPowerAuthClientToken(String powerAuthClientToken) {
        this.powerAuthClientToken = powerAuthClientToken;
    }

    /**
     * Get HTTP basic authentication password.
     * @return HTTP basic authentication password.
     */
    public String getPowerAuthClientSecret() {
        return powerAuthClientSecret;
    }

    /**
     * Set HTTP basic authentication password.
     * @param powerAuthClientSecret HTTP basic authentication password.
     */
    public void setPowerAuthClientSecret(String powerAuthClientSecret) {
        this.powerAuthClientSecret = powerAuthClientSecret;
    }

    /**
     * Get whether SSL certificate errors are ignored.
     * @return Whether SSL certificate errors are ignored.
     */
    public boolean getAcceptInvalidSslCertificate() {
        return acceptInvalidSslCertificate;
    }

    /**
     * Set whether SSL certificate errors are ignored.
     * @param acceptInvalidSslCertificate Whether SSL certificate errors are ignored.
     */
    public void setAcceptInvalidSslCertificate(boolean acceptInvalidSslCertificate) {
        this.acceptInvalidSslCertificate = acceptInvalidSslCertificate;
    }
}
