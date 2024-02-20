/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import lombok.Data;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.*;

/**
 * Configuration class for PowerAuth Controller tests.
 * <p>
 * This class provides configuration settings and helper methods
 * for testing PowerAuth Controller. It includes methods for initializing
 * test data, creating applications, managing activations, and handling
 * other necessary setup for conducting tests effectively.
 * </p>
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Configuration
@Data
public class PowerAuthControllerTestConfig {

    private static final String POWERAUTH_REST_URL = "http://localhost:9999/rest";
    protected static final String PUBLIC_KEY_RECOVERY_POSTCARD_BASE64 = "BABXgGoj4Lizl3GN0rjrtileEEwekFkpX1ERS9yyYjyuM1Iqdti3ihtATBxk5XGvjetPO1YC+qXciUYjIsETtbI=";
    protected static final String USER_ID = "test-user";
    protected static final String DATA = "A2";
    protected static final String CALLBACK_NAME = UUID.randomUUID().toString();
    protected static final String CALLBACK_URL = "http://test.test";
    protected static final String PROTOCOL_VERSION = "3.2";

    private String applicationId;
    private String applicationVersionId;
    private String applicationKey;
    private String applicationSecret;
    private String masterPublicKey;
    private String applicationVersion = "default" + "_" + System.currentTimeMillis();
    private final String applicationName = "Pa_tests_component";
    private Long loginOperationTemplateId;
    private String loginOperationTemplateName;
    private String activationId;
    private String activationCode;
    private String activationName;

    /**
     * Creates and configures a new {@link PowerAuthClient} bean.
     * <p>
     * The method configures and returns a PowerAuthClient instance for interacting with
     * the PowerAuth Server. It sets up the client with the necessary configurations such as
     * accepting invalid SSL certificates for testing purposes.
     *
     * @return A configured instance of PowerAuthClient
     * @throws Exception if there is an issue creating the PowerAuthClient instance
     */
    @Bean
    public PowerAuthClient powerAuthClient() throws Exception {
        final PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
        config.setAcceptInvalidSslCertificate(true);
        return new PowerAuthRestClient(POWERAUTH_REST_URL);
    }

}
