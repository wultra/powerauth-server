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

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior.CONFIG_KEY_CRYPTO_SUPPORTED_ALGORITHMS;

/**
 * Service for listing supported algorithms.
 *
 * @author Roman Strobl
 */
@Service
@Slf4j
@AllArgsConstructor
public class AlgorithmQueryService {

    private final ApplicationConfigServiceBehavior applicationConfigServiceBehavior;
    private final PowerAuthServiceConfiguration configuration;

    /**
     * Check whether a shared secret algorithm is supported for a given application.
     * @param application Application.
     * @param sharedSecretAlgorithm Shared secret algorithm.
     * @return Whether the algorithm is supported.
     */
    public boolean isAlgorithmSupported(ApplicationEntity application, SharedSecretAlgorithm sharedSecretAlgorithm) {
        final List<String> supportedAlgorithms = fetchSupportedAlgorithms(application);
        return isAlgorithmAllowed(sharedSecretAlgorithm, supportedAlgorithms)
                && isAlgorithmSupportedByProtocol(sharedSecretAlgorithm);
    }

    /**
     * Check whether any of the provided shared secret algorithms is supported for a given application.
     * @param application Application.
     * @param algorithms List of shared secret algorithms to check.
     * @return {@code true} if at least one algorithm is supported, {@code false} otherwise.
     */
    public boolean isAnyAlgorithmSupported(ApplicationEntity application, List<SharedSecretAlgorithm> algorithms) {
        if (algorithms == null || algorithms.isEmpty()) {
            return false;
        }
        final List<String> supportedAlgorithms = fetchSupportedAlgorithms(application);
        return algorithms.stream()
                .anyMatch(algorithm -> isAlgorithmAllowed(algorithm, supportedAlgorithms)
                        && isAlgorithmSupportedByProtocol(algorithm));
    }

    /**
     * Get the list of supported shared secret algorithms for an application.
     * @param application Application.
     * @return List of supported shared secret algorithms.
     */
    public List<SharedSecretAlgorithm> getSupportedAlgorithms(ApplicationEntity application) {
        final List<String> supportedAlgorithms = fetchSupportedAlgorithms(application);
        return Stream.of(SharedSecretAlgorithm.values())
                .filter(algorithm -> isAlgorithmAllowed(algorithm, supportedAlgorithms))
                .filter(this::isAlgorithmSupportedByProtocol)
                .toList();
    }

    /**
     * Load allowed algorithm values from configuration for the given application.
     */
    private List<String> fetchSupportedAlgorithms(ApplicationEntity application) {
        final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
        configRequest.setApplicationId(application.getId());
        final GetApplicationConfigResponse configResponse =
                applicationConfigServiceBehavior.getApplicationConfig(configRequest);

        return configResponse.getApplicationConfigs().stream()
                .filter(config -> CONFIG_KEY_CRYPTO_SUPPORTED_ALGORITHMS.equals(config.getKey()))
                .findFirst()
                .map(ApplicationConfigurationItem::getValues)
                .map(values -> values.stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .collect(Collectors.toList()))
                .orElse(Collections.emptyList());
    }

    /**
     * Determines whether the algorithm is allowed based on configuration values.
     */
    private boolean isAlgorithmAllowed(SharedSecretAlgorithm algorithm, List<String> allowedValues) {
        // PQC-only algorithms are currently not allowed until they mature
        if (algorithm == SharedSecretAlgorithm.ML_L3 || algorithm == SharedSecretAlgorithm.ML_L5) {
            return false;
        }

        // All other algorithms are allowed if the configuration list is empty
        return allowedValues.isEmpty() || allowedValues.contains(algorithm.name());
    }

    /**
     * Determines whether the algorithm is supported based on protocol version.
     */
    private boolean isAlgorithmSupportedByProtocol(SharedSecretAlgorithm algorithm) {
        // Check whether protocol version 3 is supported at all
        return !(algorithm == SharedSecretAlgorithm.EC_P256 && configuration.getMinSupportedProtocolVersion() > 3);
    }

}
