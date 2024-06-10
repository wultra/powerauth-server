/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.rest.client;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import java.time.Duration;

/**
 * Configuration of PowerAuth FIDO2 REST client.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Getter @Setter
public class PowerAuthFido2RestClientConfiguration {

    // Use 1 MB as default maximum memory size
    private int maxMemorySize = 1024 * 1024;
    // Use 5 seconds as default connect timeout
    private Duration connectTimeout = Duration.ofMillis(5000);

    /**
     * The maximum duration allowed between each network-level read operations.
     */
    private Duration responseTimeout;

    /**
     * The options to use for configuring ConnectionProvider max idle time. {@code Null} means no max idle time.
     */
    private Duration maxIdleTime;

    /**
     * The options to use for configuring ConnectionProvider max life time. {@code Null} means no max life time.
     */
    private Duration maxLifeTime;

    private boolean proxyEnabled = false;
    private String proxyHost;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;
    private String powerAuthClientToken;
    private String powerAuthClientSecret;
    private boolean acceptInvalidSslCertificate;
    private HttpHeaders defaultHttpHeaders;
    private ExchangeFilterFunction filter;

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
     * Get connection timeout as a Duration.
     * @return Connection timeout as a Duration.
     */
    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * Set connection timeout as a Duration.
     * @param connectTimeout Connection timeout as a Duration.
     */
    public void setConnectTimeout(Duration connectTimeout) {
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

    /**
     * Get default HTTP headers.
     * @return Default HTTP headers.
     */
    public HttpHeaders getDefaultHttpHeaders() {
        return defaultHttpHeaders;
    }

    /**
     * Set default HTTP headers.
     * @param defaultHttpHeaders Default HTTP headers.
     */
    public void setDefaultHttpHeaders(HttpHeaders defaultHttpHeaders) {
        this.defaultHttpHeaders = defaultHttpHeaders;
    }

    /**
     * Get exchange filter function.
     * @return Exchange filter function.
     */
    public ExchangeFilterFunction getFilter() {
        return filter;
    }

    /**
     * Set exchange filter function.
     * @param filter Exchange filter function.
     */
    public void setFilter(ExchangeFilterFunction filter) {
        this.filter = filter;
    }

}
