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

    /**
     * Maximum memory size for HTTP requests in bytes. Use 1 MB as default maximum memory size.
     */
    private int maxMemorySize = 1024 * 1024;

    /**
     * Connection timeout. Use 5 seconds as default value.
     */
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

    /**
     * Whether HTTP proxy is enabled.
     */
    private boolean proxyEnabled = false;

    /**
     * Proxy host.
     */
    private String proxyHost;

    /**
     * Proxy port.
     */
    private int proxyPort;

    /**
     * Proxy username.
     */
    private String proxyUsername;

    /**
     * Proxy password.
     */
    private String proxyPassword;

    /**
     * HTTP basic authentication username.
     */
    private String powerAuthClientToken;

    /**
     * HTTP basic authentication password.
     */
    private String powerAuthClientSecret;

    /**
     * Whether SSL certificate errors are ignored.
     */
    private boolean acceptInvalidSslCertificate;

    /**
     * Default HTTP headers.
     */
    private HttpHeaders defaultHttpHeaders;

    /**
     * Exchange filter function.
     */
    private ExchangeFilterFunction filter;

}
