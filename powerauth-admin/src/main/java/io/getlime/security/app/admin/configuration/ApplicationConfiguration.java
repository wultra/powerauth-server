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

    @Value("${powerauth.admin.service.applicationName}")
    private String applicationName;

    @Value("${powerauth.admin.service.applicationDisplayName}")
    private String applicationDisplayName;

    @Value("${powerauth.admin.service.applicationEnvironment}")
    private String applicationEnvironment;

    /**
     * Specifies the proportion of requests that are sampled for tracing.
     */
    @Value("${management.tracing.sampling.probability}")
    private double tracingSamplingProbability;

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

    /**
     * Retrieves the sampling probability for tracing.
     * This value determines the proportion of requests that are sampled for tracing purposes.
     *
     * @return The current tracing sampling probability.
     */
    public double getTracingSamplingProbability() {
        return tracingSamplingProbability;
    }

    /**
     * Sets the sampling probability for tracing.
     * This value determines the proportion of requests that are sampled for tracing purposes.
     *
     * @param tracingSamplingProbability The tracing sampling probability to be set.
     */
    public void setTracingSamplingProbability(final double tracingSamplingProbability) {
        this.tracingSamplingProbability = tracingSamplingProbability;
    }

}
