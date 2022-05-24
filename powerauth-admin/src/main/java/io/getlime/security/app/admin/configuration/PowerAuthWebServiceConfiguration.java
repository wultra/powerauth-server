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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * PowerAuth REST WebService Configuration.
 *
 * @author Petr Dvorak
 */
@Configuration
public class PowerAuthWebServiceConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthWebServiceConfiguration.class);

    private final ApplicationConfiguration configuration;

    @Autowired
    public PowerAuthWebServiceConfiguration(ApplicationConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Checks if given client token is the current client token.
     * @param clientToken Client Token to be checked.
     * @return True if the provided client token is the same one as the one being used, false otherwise.
     */
    public boolean isCurrentSecuritySettings(String clientToken) {
        return this.configuration.getClientToken() != null
                && this.configuration.getClientToken().equals(clientToken);
    }

    /**
     * Initialize PowerAuth REST client.
     * @return PowerAuth REST client.
     */
    @Bean
    public PowerAuthClient powerAuthClient() {
        PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
        config.setPowerAuthClientToken(configuration.getClientToken());
        config.setPowerAuthClientSecret(configuration.getClientSecret());
        config.setAcceptInvalidSslCertificate(configuration.isAcceptInvalidSslCertificate());
        try {
            return new PowerAuthRestClient(configuration.getPowerAuthServiceUrl(), config);
        } catch (PowerAuthClientException ex) {
            // Log the error in case Rest client initialization failed
            logger.error(ex.getMessage(), ex);
            return null;
        }
    }


}