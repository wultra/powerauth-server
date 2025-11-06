/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior.CONFIG_KEY_CRYPTO_SUPPORTED_ALGORITHMS;

/**
 * Service for listing supported algorithms.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class AlgorithmQueryService {

    private final ApplicationConfigServiceBehavior applicationConfigServiceBehavior;

    /**
     * Get whether shared secret algorithm is allowed based on configuration of allowed algorithms.
     * @param application Application.
     * @param sharedSecretAlgorithm Shared secret algorithm.
     * @return Whether shared secret algorithm is allowed.
     */
    public boolean isAlgorithmSupported(ApplicationEntity application, SharedSecretAlgorithm sharedSecretAlgorithm) {
        GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
        configRequest.setApplicationId(application.getId());

        GetApplicationConfigResponse configResponse = applicationConfigServiceBehavior.getApplicationConfig(configRequest);
        List<ApplicationConfigurationItem> configs = configResponse.getApplicationConfigs();

        // PQC-only algorithms are currently not allowed until they mature
        if (sharedSecretAlgorithm == SharedSecretAlgorithm.ML_L3 || sharedSecretAlgorithm == SharedSecretAlgorithm.ML_L5) {
            return false;
        }

        final Optional<ApplicationConfigurationItem> allowedAlgorithmsConfig = configs.stream()
                .filter(config -> CONFIG_KEY_CRYPTO_SUPPORTED_ALGORITHMS.equals(config.getKey()))
                .findFirst();

        // All other algorithms are allowed by default
        if (allowedAlgorithmsConfig.isEmpty() || allowedAlgorithmsConfig.get().getValues().isEmpty()) {
            return true;
        }

        final ApplicationConfigurationItem configurationItem = allowedAlgorithmsConfig.get();
        return configurationItem.getValues().contains(sharedSecretAlgorithm.name());
    }

    /**
     * Get the list of supported shared secret algorithms for an application.
     * @param application Application.
     * @return List of supported shared secret algorithms.
     */
    public List<SharedSecretAlgorithm> getSupportedAlgorithms(ApplicationEntity application) {
        return Stream.of(SharedSecretAlgorithm.values())
                .filter(algorithm -> isAlgorithmSupported(application, algorithm))
                .toList();
    }

}
