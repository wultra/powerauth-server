/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.netty.channel.ChannelOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.ProxyProvider;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Class that manages the service logic related to callback URL management.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class CallbackUrlBehavior {

    private final CallbackUrlRepository callbackUrlRepository;

    private LocalizationProvider localizationProvider;

    private WebClient webClient;

    private PowerAuthServiceConfiguration configuration;

    // HTTP proxy settings
    private boolean proxyEnabled;
    private String proxyHost;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;

    // HTTP connection timeout
    private Integer connectionTimeout;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(CallbackUrlBehavior.class);

    @Autowired
    public CallbackUrlBehavior(CallbackUrlRepository callbackUrlRepository) {
        this.callbackUrlRepository = callbackUrlRepository;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Configure WebClient HTTP connection parameters.
     */
    private void configureWebClient() {
        proxyEnabled = configuration.getHttpProxyEnabled();
        if (proxyEnabled) {
            proxyHost = configuration.getHttpProxyHost();
            proxyPort = configuration.getHttpProxyPort();
            proxyUsername = configuration.getHttpProxyUsername();
            proxyPassword = configuration.getHttpProxyPassword();
        }
        this.connectionTimeout = configuration.getHttpConnectionTimeout();
    }

    /**
     * Initialize WebClient instance and configure it based on client configuration.
     */
    private void initializeWebClient() {
        HttpClient httpClient = HttpClient.create()
                .tcpConfiguration(tcpClient -> {
                            if (connectionTimeout != null) {
                                tcpClient = tcpClient.option(
                                        ChannelOption.CONNECT_TIMEOUT_MILLIS,
                                        connectionTimeout);
                            }
                            if (proxyEnabled) {
                                tcpClient = tcpClient.proxy(proxySpec -> {
                                    ProxyProvider.Builder builder = proxySpec
                                            .type(ProxyProvider.Proxy.HTTP)
                                            .host(proxyHost)
                                            .port(proxyPort);
                                    if (proxyUsername != null && !proxyUsername.isEmpty()) {
                                        builder.username(proxyUsername);
                                        builder.password(s -> proxyPassword);
                                    }
                                    builder.build();
                                });
                            }
                            return tcpClient;
                        }
                );
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        webClient = WebClient.builder().clientConnector(connector).build();
    }

    /**
     * Creates a new callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Newly created callback URL record.
     * @throws GenericServiceException Thrown when callback URL in request is malformed.
     */
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws GenericServiceException {

        // Check the URL format
        try {
            new URL(request.getCallbackUrl());
        } catch (MalformedURLException e) {
            logger.warn("Invalid callback URL: "+request.getCallbackUrl());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
        }

        CallbackUrlEntity entity = new CallbackUrlEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setApplicationId(request.getApplicationId());
        entity.setName(request.getName());
        entity.setCallbackUrl(request.getCallbackUrl());
        entity.setAttributes(request.getAttributes());
        callbackUrlRepository.save(entity);
        CreateCallbackUrlResponse response = new CreateCallbackUrlResponse();
        response.setId(entity.getId());
        response.setApplicationId(entity.getApplicationId());
        response.setName(entity.getName());
        response.setCallbackUrl(entity.getCallbackUrl());
        return response;
    }

    /**
     * Update a callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Update callback URL record.
     * @throws GenericServiceException Thrown when callback URL in request is malformed or callback URL could not be found.
     */
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws GenericServiceException {

        if (request.getId() == null) {
            logger.warn("Missing callback ID");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        Optional<CallbackUrlEntity> entityOptional = callbackUrlRepository.findById(request.getId());
        if (!entityOptional.isPresent()) {
            logger.warn("Invalid callback ID: "+request.getId());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Check the URL format
        try {
            new URL(request.getCallbackUrl());
        } catch (MalformedURLException e) {
            logger.warn("Invalid callback URL: "+request.getCallbackUrl());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
        }

        CallbackUrlEntity entity = entityOptional.get();
        entity.setName(request.getName());
        entity.setCallbackUrl(request.getCallbackUrl());
        entity.setAttributes(request.getAttributes());
        callbackUrlRepository.save(entity);
        UpdateCallbackUrlResponse response = new UpdateCallbackUrlResponse();
        response.setId(entity.getId());
        response.setApplicationId(entity.getApplicationId());
        response.setName(entity.getName());
        response.setCallbackUrl(entity.getCallbackUrl());
        response.getAttributes().addAll(entity.getAttributes());
        return response;
    }

    /**
     * Get the list of all current callback URLs for given application.
     * @param request Request with application ID to fetch the callback URL agains.
     * @return List of all current callback URLs.
     */
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) {
        final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdOrderByName(request.getApplicationId());
        GetCallbackUrlListResponse response = new GetCallbackUrlListResponse();
        for (CallbackUrlEntity callbackUrl: callbackUrlEntities) {
            GetCallbackUrlListResponse.CallbackUrlList item = new GetCallbackUrlListResponse.CallbackUrlList();
            item.setId(callbackUrl.getId());
            item.setApplicationId(callbackUrl.getApplicationId());
            item.setName(callbackUrl.getName());
            item.setCallbackUrl(callbackUrl.getCallbackUrl());
            item.getAttributes().addAll(callbackUrl.getAttributes());
            response.getCallbackUrlList().add(item);
        }
        return response;
    }

    /**
     * Remove callback URL with given ID.
     * @param request Request specifying the callback URL to be removed.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) {
        RemoveCallbackUrlResponse response = new RemoveCallbackUrlResponse();
        response.setId(request.getId());
        final Optional<CallbackUrlEntity> callbackUrlEntityOptional = callbackUrlRepository.findById(request.getId());
        if (callbackUrlEntityOptional.isPresent()) {
            callbackUrlRepository.delete(callbackUrlEntityOptional.get());
            response.setRemoved(true);
        } else {
            response.setRemoved(false);
        }
        return response;
    }

    /**
     * Tries to asynchronously notify all callbacks that are registered for given application.
     * @param applicationId Application for the callbacks to be used.
     * @param activation Activation to be notified about.
     */
    public void notifyCallbackListeners(Long applicationId, ActivationRecordEntity activation) {
        if (webClient == null) {
            // Initialize Web Client when it is used for the first time
            configureWebClient();
            initializeWebClient();
        }
        final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdOrderByName(applicationId);
        for (CallbackUrlEntity callbackUrlEntity: callbackUrlEntities) {
            Map<String, Object> callbackData = prepareCallbackData(callbackUrlEntity, activation);
            Consumer<ClientResponse> onSuccess = response -> {
                if (response.statusCode().isError()) {
                    logger.warn("Callback failed, URL: {}, status code: {}", callbackUrlEntity.getCallbackUrl(), response.statusCode().toString());
                }
            };
            Consumer<Throwable> onError = error -> logger.warn( "Callback failed, URL: {}, error: {}", callbackUrlEntity.getCallbackUrl(), error.getMessage());
            webClient
                    .post()
                    .uri(callbackUrlEntity.getCallbackUrl())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(callbackData))
                    .exchange()
                    .subscribe(onSuccess, onError);
        }
    }

    /**
     * Prepare callback data for given callback URL entity and activation entity.
     * @param callbackUrlEntity Callback URL entity.
     * @param activation Activation entity.
     * @return Callback data to send.
     */
    private Map<String, Object> prepareCallbackData(CallbackUrlEntity callbackUrlEntity, ActivationRecordEntity activation) {
        Map<String, Object> callbackData = new HashMap<>();
        callbackData.put("activationId", activation.getActivationId());
        if (callbackUrlEntity.getAttributes().contains("userId")) {
            callbackData.put("userId", activation.getUserId());
        }
        if (callbackUrlEntity.getAttributes().contains("activationName")) {
            callbackData.put("activationName", activation.getActivationName());
        }
        if (callbackUrlEntity.getAttributes().contains("deviceInfo")) {
            callbackData.put("deviceInfo", activation.getDeviceInfo());
        }
        if (callbackUrlEntity.getAttributes().contains("platform")) {
            callbackData.put("platform", activation.getPlatform());
        }
        if (callbackUrlEntity.getAttributes().contains("activationFlags")) {
            callbackData.put("activationFlags", activation.getFlags());
        }
        if (callbackUrlEntity.getAttributes().contains("activationStatus")) {
            callbackData.put("activationStatus", activation.getActivationStatus());
        }
        if (callbackUrlEntity.getAttributes().contains("blockedReason")) {
            callbackData.put("blockedReason", activation.getBlockedReason());
        }
        if (callbackUrlEntity.getAttributes().contains("applicationId")) {
            callbackData.put("applicationId", activation.getApplication().getId());
        }
        return callbackData;
    }

}
