package io.getlime.security.powerauth.app.server.service.callbacks;

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manager class for REST Client instances used to Callback URL Event processing.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@AllArgsConstructor
@Component
@Slf4j
public class CallbackUrlRestClientManager {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final CallbackUrlAuthenticationCryptor callbackUrlAuthenticationCryptor;
    private final CallbackUrlEventRepository callbackUrlEventRepository;

    // Store REST clients in cache with their callback ID as a key
    private final Map<String, RestClient> restClientCache = new ConcurrentHashMap<>();
    private final Object restClientCacheLock = new Object();

    /**
     * Get a REST Client using which a Callback URL Event will be dispatched.
     * @param callbackUrlEvent Callback URL Event for which to get the REST Client.
     * @return REST Client.
     * @throws RestClientException In case the REST Client initialization fails.
     */
    public RestClient getRestClient(final CallbackUrlEvent callbackUrlEvent) throws RestClientException, GenericServiceException {
        final String cacheKey = callbackUrlEvent.restClientCacheKey();
        synchronized (restClientCacheLock) {
            final RestClient restClient = restClientCache.get(cacheKey);
            if (restClient == null) {
                logger.debug("REST client not found in cache, initializing new REST client, callback cache key: {}", cacheKey);
                return createRestClientAndStoreInCache(callbackUrlEvent);
            } else {
                logger.debug("REST client found in cache, callback cache key: {}", cacheKey);
                return restClient;
            }
        }
    }

    /**
     * Get a key for the REST client cache from a callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     * @return Cache key.
     */
    private String getRestClientCacheKey(final CallbackUrlEntity callbackUrlEntity) {
        return callbackUrlEntity.getId();
    }

    /**
     * Create a new REST Client for a Callback URL Configuration and store it in a cache.
     * @param callbackUrlEvent Callback URL Event for which to create the REST Client.
     * @return Rest client.
     */
    private RestClient createRestClientAndStoreInCache(final CallbackUrlEvent callbackUrlEvent) throws RestClientException, GenericServiceException {
        final CallbackUrlEventEntity callbackUrlEventEntity = callbackUrlEventRepository.findById(callbackUrlEvent.callbackUrlEventEntityId())
                .orElseThrow(() -> new IllegalStateException("Callback Url Event was not found in database during REST Client initialization: callbackUrlEventId=" + callbackUrlEvent.callbackUrlEventEntityId()));

        final RestClient restClient = initializeRestClient(callbackUrlEventEntity.getCallbackUrlEntity());
        restClientCache.put(callbackUrlEvent.restClientCacheKey(), restClient);
        return restClient;
    }

    /**
     * Evict an instance from REST client cache for given callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     */
    public void evictRestClientFromCache(final CallbackUrlEntity callbackUrlEntity) {
        synchronized (restClientCacheLock) {
            restClientCache.remove(getRestClientCacheKey(callbackUrlEntity));
        }
    }

    /**
     * Initialize Rest client instance and configure it based on client configuration.
     * @param callbackUrlEntity Callback URL entity.
     */
    private RestClient initializeRestClient(final CallbackUrlEntity callbackUrlEntity) throws RestClientException, GenericServiceException {
        final DefaultRestClient.Builder builder = DefaultRestClient.builder();
        if (powerAuthServiceConfiguration.getHttpConnectionTimeout() != null) {
            builder.connectionTimeout(powerAuthServiceConfiguration.getHttpConnectionTimeout());
        }
        if (powerAuthServiceConfiguration.getHttpResponseTimeout() != null) {
            builder.responseTimeout(powerAuthServiceConfiguration.getHttpResponseTimeout());
        }
        if (powerAuthServiceConfiguration.getHttpMaxIdleTime() != null) {
            builder.maxIdleTime(powerAuthServiceConfiguration.getHttpMaxIdleTime());
        }
        if (Boolean.TRUE.equals(powerAuthServiceConfiguration.getHttpProxyEnabled())) {
            final DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(powerAuthServiceConfiguration.getHttpProxyHost()).port(powerAuthServiceConfiguration.getHttpProxyPort());
            if (powerAuthServiceConfiguration.getHttpProxyUsername() != null) {
                proxyBuilder.username(powerAuthServiceConfiguration.getHttpProxyUsername()).password(powerAuthServiceConfiguration.getHttpProxyPassword());
            }
        }
        final CallbackUrlAuthentication authentication = callbackUrlAuthenticationCryptor.decrypt(callbackUrlEntity);
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
