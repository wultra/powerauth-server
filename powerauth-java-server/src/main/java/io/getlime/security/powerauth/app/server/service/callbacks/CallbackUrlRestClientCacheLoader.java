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

package io.getlime.security.powerauth.app.server.service.callbacks;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CachedRestClient;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Specialization of {@link CacheLoader} for {@link CachedRestClient}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@AllArgsConstructor
@Slf4j
@Component
public class CallbackUrlRestClientCacheLoader implements CacheLoader<String, CachedRestClient> {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final CallbackUrlAuthenticationEncryptor callbackUrlAuthenticationEncryptor;
    private final CallbackUrlRepository callbackUrlRepository;

    @Override
    public @Nullable CachedRestClient load(final String callbackUrlId) throws RestClientException, GenericServiceException {
        logger.debug("Loading RestClient for CallbackUrl: id={}", callbackUrlId);

        final Optional<CallbackUrlEntity> optionalCallbackUrlEntity = callbackUrlRepository.findById(callbackUrlId);
        if (optionalCallbackUrlEntity.isEmpty()) {
            logger.warn("CallbackUrlEntity is not available: id={}", callbackUrlId);
            return null;
        }

        final RestClient restClient = initializeRestClient(optionalCallbackUrlEntity.get());
        return new CachedRestClient(restClient, LocalDateTime.now());
    }

    @Override
    public @Nullable CachedRestClient reload(final String callbackUrlId, final CachedRestClient cachedRestClient) throws RestClientException, GenericServiceException {
        logger.debug("Checking cached RestClient for CallbackUrl: id={}", callbackUrlId);

        final Optional<CallbackUrlEntity> optionalCallbackUrlEntity = callbackUrlRepository.findById(callbackUrlId);
        if (optionalCallbackUrlEntity.isEmpty()) {
            logger.warn("CallbackUrlEntity is not available anymore: id={}", callbackUrlId);
            return null;
        }

        final LocalDateTime lastEntityUpdate = optionalCallbackUrlEntity.get().getTimestampLastUpdated();
        if (lastEntityUpdate != null && lastEntityUpdate.isAfter(cachedRestClient.timestampCreated())) {
            final RestClient restClient = initializeRestClient(optionalCallbackUrlEntity.get());
            return new CachedRestClient(restClient, LocalDateTime.now());
        }

        logger.debug("Keeping the RestClient in cache for CallbackUrl: id={}", callbackUrlId);
        return cachedRestClient;
    }

    /**
     * Initialize Rest client instance and configure it based on client configuration.
     * @param callbackUrlEntity Callback URL entity.
     * @throws RestClientException In case the REST Client initialization fails.
     * @throws GenericServiceException In case the Callback URL Authentication decryption fails.
     */
    private RestClient initializeRestClient(final CallbackUrlEntity callbackUrlEntity) throws RestClientException, GenericServiceException {
        logger.debug("Initiating a new RestClient for callbackUrl: id={}", callbackUrlEntity.getId());
        final DefaultRestClient.Builder builder = DefaultRestClient.builder();
        builder.connectionTimeout(powerAuthServiceConfiguration.getHttpConnectionTimeout());
        builder.responseTimeout(powerAuthServiceConfiguration.getHttpResponseTimeout());
        builder.maxIdleTime(powerAuthServiceConfiguration.getHttpMaxIdleTime());
        if (Boolean.TRUE.equals(powerAuthServiceConfiguration.getHttpProxyEnabled())) {
            builder.proxy()
                    .host(powerAuthServiceConfiguration.getHttpProxyHost())
                    .port(powerAuthServiceConfiguration.getHttpProxyPort())
                    .username(powerAuthServiceConfiguration.getHttpProxyUsername())
                    .password(powerAuthServiceConfiguration.getHttpProxyPassword());
        }
        final CallbackUrlAuthentication authentication = callbackUrlAuthenticationEncryptor.decrypt(callbackUrlEntity);
        final CallbackUrlAuthentication.Certificate certificateAuth = authentication.getCertificate();
        if (certificateAuth != null && certificateAuth.isEnabled()) {
            final DefaultRestClient.CertificateAuthBuilder certificateAuthBuilder = builder.certificateAuth();
            if (certificateAuth.isUseCustomKeyStore()) {
                certificateAuthBuilder.enableCustomKeyStore()
                        .keyStoreLocation(certificateAuth.getKeyStoreLocation())
                        .keyStorePassword(certificateAuth.getKeyStorePassword())
                        .keyAlias(certificateAuth.getKeyAlias())
                        .keyPassword(certificateAuth.getKeyPassword());
            }
            if (certificateAuth.isUseCustomTrustStore()) {
                certificateAuthBuilder.enableCustomTruststore()
                        .trustStoreLocation(certificateAuth.getTrustStoreLocation())
                        .trustStorePassword(certificateAuth.getTrustStorePassword());
            }
        }
        final CallbackUrlAuthentication.HttpBasic httpBasicAuth = authentication.getHttpBasic();
        if (httpBasicAuth != null && httpBasicAuth.isEnabled()) {
            builder.httpBasicAuth()
                    .username(httpBasicAuth.getUsername())
                    .password(httpBasicAuth.getPassword());
        }

        final CallbackUrlAuthentication.OAuth2 oAuth2Config = authentication.getOAuth2();
        if (oAuth2Config != null && oAuth2Config.isEnabled()) {
            builder.filter(configureOAuth2ExchangeFilter(oAuth2Config, callbackUrlEntity.getId()));
        }

        return builder.build();
    }

    private static ServerOAuth2AuthorizedClientExchangeFilterFunction configureOAuth2ExchangeFilter(final CallbackUrlAuthentication.OAuth2 config, final String callbackId) {
        logger.debug("Configuring OAuth2 for callback ID: {}", callbackId);
        final String registrationId = "callback OAuth2";
        final ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(registrationId)
                .tokenUri(config.getTokenUri())
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .scope(config.getScope())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        final ReactiveClientRegistrationRepository clientRegistrations = new InMemoryReactiveClientRegistrationRepository(clientRegistration);
        final ReactiveOAuth2AuthorizedClientService clientService = new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrations);

        final AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(clientRegistrations, clientService);
        final ServerOAuth2AuthorizedClientExchangeFilterFunction oAuth2ExchangeFilterFunction = new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oAuth2ExchangeFilterFunction.setDefaultClientRegistrationId(registrationId);
        return oAuth2ExchangeFilterFunction;
    }

}
