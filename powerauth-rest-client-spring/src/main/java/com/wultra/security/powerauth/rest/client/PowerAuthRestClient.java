/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.client;

import com.fasterxml.jackson.databind.type.TypeFactory;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.ProxyProvider;

import javax.net.ssl.SSLException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.lang.reflect.Type;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Class implementing a PowerAuth REST client.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthRestClient implements PowerAuthClient {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthRestClient.class);

    private static final String PA_REST_V3_PREFIX = "/v3";

    private String baseUrl;

    private final WebClient webClient;

    /**
     * PowerAuth REST client constructor.
     *
     * @param baseUrl BASE URL of REST endpoints.
     */
    public PowerAuthRestClient(String baseUrl) {
        this(baseUrl, new PowerAuthRestClientConfiguration());
    }

    /**
     * PowerAuth REST client constructor.
     *
     * @param baseUrl BASE URL of REST endpoints.
     */
    public PowerAuthRestClient(String baseUrl, PowerAuthRestClientConfiguration config) {
        WebClient.Builder builder = WebClient.builder().baseUrl(baseUrl);
        HttpClient httpClient = HttpClient.create();
        SslContext sslContext;
        try {
            if (config.getSkipSslCertificateValidation()) {
                sslContext = SslContextBuilder
                        .forClient()
                        .trustManager(InsecureTrustManagerFactory.INSTANCE)
                        .build();
                httpClient = httpClient.secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));
            }
        } catch (SSLException ex) {
            logger.warn(ex.getMessage(), ex);
        }
        httpClient = httpClient.tcpConfiguration(tcpClient -> {
            tcpClient = tcpClient.option(
                    ChannelOption.CONNECT_TIMEOUT_MILLIS,
                    config.getConnectTimeout());
            if (config.isProxyEnabled()) {
                tcpClient = tcpClient.proxy(proxySpec -> {
                    ProxyProvider.Builder proxyBuilder = proxySpec
                            .type(ProxyProvider.Proxy.HTTP)
                            .host(config.getProxyHost())
                            .port(config.getProxyPort());
                    if (config.getProxyUsername() != null) {
                        proxyBuilder.username(config.getProxyUsername());
                        proxyBuilder.password(s -> config.getProxyPassword());
                    }
                    proxyBuilder.build();
                });
            }
            return tcpClient;
        });
        builder.exchangeStrategies(ExchangeStrategies.builder()
                .codecs(configurer -> configurer
                        .defaultCodecs()
                        .maxInMemorySize(config.getMaxMemorySize()))
                .build());
        if (config.getPowerAuthClientToken() != null) {
            builder.filter(ExchangeFilterFunctions
                    .basicAuthentication(config.getPowerAuthClientToken(), config.getPowerAuthClientSecret()))
                    .build();
        }
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        this.webClient = builder.clientConnector(connector).build();
    }

    /**
     * Call the PowerAuth v3 API.
     *
     * @param path Path of the endpoint.
     * @param request Request object.
     * @param responseType Response type.
     * @return Response.
     */
    private <T> T callV3RestApi(String path, Object request, Class<T> responseType) {
        ObjectRequest<?> objectRequest = new ObjectRequest<>(request);
        ParameterizedTypeReference<ObjectResponse<T>> typeReference = new ParameterizedTypeReference<ObjectResponse<T>>(){
            @Override
            public Type getType() {
                return TypeFactory.defaultInstance().constructParametricType(ObjectResponse.class, responseType);
            }
        };
        ObjectResponse<T> objectResponse = webClient.post()
                .uri(PA_REST_V3_PREFIX + path)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(objectRequest))
                .retrieve()
                .bodyToMono(typeReference)
                .block();
        if (objectResponse == null) {
            return null;
        }
        return objectResponse.getResponseObject();
    }

    /**
     * Convert date to XMLGregorianCalendar
     *
     * @param date Date to be converted.
     * @return A new instance of {@link XMLGregorianCalendar}.
     */
    private XMLGregorianCalendar calendarWithDate(Date date) {
        try {
            GregorianCalendar c = new GregorianCalendar();
            c.setTime(date);
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
        } catch (DatatypeConfigurationException e) {
            // Unless there is a terrible configuration error, this should not happen
            logger.error("Unable to prepare a new calendar instance", e);
        }
        return null;
    }

    @Override
    public GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) {
        return callV3RestApi("/status", request, GetSystemStatusResponse.class);
    }

    @Override
    public GetSystemStatusResponse getSystemStatus() {
        GetSystemStatusRequest request = new GetSystemStatusRequest();
        return getSystemStatus(request);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) {
        return callV3RestApi("/error/list", request, GetErrorCodeListResponse.class);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(String language) {
        GetErrorCodeListRequest request = new GetErrorCodeListRequest();
        request.setLanguage(language);
        return getErrorList(request);
    }

    @Override
    public InitActivationResponse initActivation(InitActivationRequest request) {
        return callV3RestApi("/activation/init", request, InitActivationResponse.class);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId) {
        return this.initActivation(userId, applicationId, null, null, ActivationOtpValidation.NONE, null);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId, ActivationOtpValidation otpValidation, String otp) {
        return this.initActivation(userId, applicationId, null, null, otpValidation, otp);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) {
        return this.initActivation(userId, applicationId, maxFailureCount, timestampActivationExpire, ActivationOtpValidation.NONE, null);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                                 ActivationOtpValidation otpValidation, String otp) {
        InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setActivationOtpValidation(otpValidation);
        request.setActivationOtp(otp);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(calendarWithDate(timestampActivationExpire));
        }
        return this.initActivation(request);
    }

    @Override
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
        return callV3RestApi("/activation/prepare", request, PrepareActivationResponse.class);
    }

    @Override
    public PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce) {
        PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return prepareActivation(request);
    }

    @Override
    public CreateActivationResponse createActivation(CreateActivationRequest request) {
        return callV3RestApi("/activation/create", request, CreateActivationResponse.class);
    }

    @Override
    public CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                                     String applicationKey, String ephemeralPublicKey, String encryptedData,
                                                     String mac, String nonce) {
        CreateActivationRequest request = new CreateActivationRequest();
        request.setUserId(userId);
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(calendarWithDate(timestampActivationExpire));
        }
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return createActivation(request);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) {
        UpdateActivationOtpRequest request = new UpdateActivationOtpRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return updateActivationOtp(request);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) {
        return callV3RestApi("/activation/otp/update", request, UpdateActivationOtpResponse.class);
    }

    @Override
    public CommitActivationResponse commitActivation(CommitActivationRequest request) {
        return callV3RestApi("/activation/commit", request, CommitActivationResponse.class);
    }

    @Override
    public CommitActivationResponse commitActivation(String activationId, String externalUserId) {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.commitActivation(request);
    }

    @Override
    public CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return this.commitActivation(request);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) {
        return callV3RestApi("/activation/status", request, GetActivationStatusResponse.class);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(String activationId) {
        GetActivationStatusResponse response = this.getActivationStatusWithEncryptedStatusBlob(activationId, null);
        response.setEncryptedStatusBlob(null);
        return response;
    }

    @Override
    public GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) {
        GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        request.setChallenge(challenge);
        return this.getActivationStatus(request);
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
        return callV3RestApi("/activation/remove", request, RemoveActivationResponse.class);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId) {
        return this.removeActivation(activationId, externalUserId, false);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId, Boolean revokeRecoveryCodes) {
        RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setRevokeRecoveryCodes(revokeRecoveryCodes);
        return this.removeActivation(request);
    }

    @Override
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) {
        return callV3RestApi("/activation/list", request, GetActivationListForUserResponse.class);
    }

    @Override
    public List<GetActivationListForUserResponse.Activations> getActivationListForUser(String userId) {
        GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(userId);
        return this.getActivationListForUser(request).getActivations();
    }

    @Override
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) {
        return callV3RestApi("/activation/lookup", request, LookupActivationsResponse.class);
    }

    @Override
    public List<LookupActivationsResponse.Activations> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) {
        LookupActivationsRequest request = new LookupActivationsRequest();
        request.getUserIds().addAll(userIds);
        if (applicationIds != null) {
            request.getApplicationIds().addAll(applicationIds);
        }
        if (timestampLastUsedBefore != null) {
            request.setTimestampLastUsedBefore(calendarWithDate(timestampLastUsedBefore));
        }
        if (timestampLastUsedAfter != null) {
            request.setTimestampLastUsedAfter(calendarWithDate(timestampLastUsedAfter));
        }
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        if (activationFlags != null) {
            request.getActivationFlags().addAll(activationFlags);
        }
        return this.lookupActivations(request).getActivations();
    }

    @Override
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) {
        return callV3RestApi("/activation/status/update", request, UpdateStatusForActivationsResponse.class);
    }

    @Override
    public UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) {
        UpdateStatusForActivationsRequest request = new UpdateStatusForActivationsRequest();
        request.getActivationIds().addAll(activationIds);
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        return this.updateStatusForActivations(request);
    }

    @Override
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
        return callV3RestApi("/signature/verify", request, VerifySignatureResponse.class);
    }

    @Override
    public VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) {
        VerifySignatureRequest request = new VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        request.setSignatureVersion(signatureVersion);
        request.setForcedSignatureVersion(forcedSignatureVersion);
        return this.verifySignature(request);
    }

    @Override
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) {
        return callV3RestApi("/signature/offline/personalized/create", request, CreatePersonalizedOfflineSignaturePayloadResponse.class);
    }

    @Override
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) {
        CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) {
        return callV3RestApi("/signature/offline/non-personalized/create", request, CreateNonPersonalizedOfflineSignaturePayloadResponse.class);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) {
        CreateNonPersonalizedOfflineSignaturePayloadRequest request = new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) {
        return callV3RestApi("/signature/offline/verify", request, VerifyOfflineSignatureResponse.class);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) {
        VerifyOfflineSignatureRequest request = new VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setAllowBiometry(allowBiometry);
        return verifyOfflineSignature(request);
    }

    @Override
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
        return callV3RestApi("/vault/unlock", request, VaultUnlockResponse.class);
    }

    @Override
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                           SignatureType signatureType, String signatureVersion, String signedData,
                                           String ephemeralPublicKey, String encryptedData, String mac, String nonce) {
        VaultUnlockRequest request = new VaultUnlockRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setSignedData(signedData);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        request.setSignatureVersion(signatureVersion);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return unlockVault(request);
    }

    @Override
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) {
        return callV3RestApi("/signature/ecdsa/verify", request, VerifyECDSASignatureResponse.class);
    }

    @Override
    public VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) {
        VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    @Override
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) {
        return callV3RestApi("/signature/list", request, SignatureAuditResponse.class);
    }

    @Override
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    @Override
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    @Override
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) {
        return callV3RestApi("/activation/history", request, ActivationHistoryResponse.class);
    }

    @Override
    public List<ActivationHistoryResponse.Items> getActivationHistory(String activationId, Date startingDate, Date endingDate) {
        ActivationHistoryRequest request = new ActivationHistoryRequest();
        request.setActivationId(activationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getActivationHistory(request).getItems();
    }

    @Override
    public BlockActivationResponse blockActivation(BlockActivationRequest request) {
        return callV3RestApi("/activation/block", request, BlockActivationResponse.class);
    }

    @Override
    public BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) {
        BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        request.setExternalUserId(externalUserId);
        return this.blockActivation(request);
    }

    @Override
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) {
        return callV3RestApi("/activation/unblock", request, UnblockActivationResponse.class);
    }

    @Override
    public UnblockActivationResponse unblockActivation(String activationId, String externalUserId) {
        UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.unblockActivation(request);
    }

    @Override
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) {
        return callV3RestApi("/application/list", request, GetApplicationListResponse.class);
    }

    @Override
    public List<GetApplicationListResponse.Applications> getApplicationList() {
        return this.getApplicationList(new GetApplicationListRequest()).getApplications();
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) {
        return callV3RestApi("/application/detail", request, GetApplicationDetailResponse.class);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(Long applicationId) {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(String applicationName) {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(applicationName);
        return this.getApplicationDetail(request);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) {
        return callV3RestApi("/application/detail/version", request, LookupApplicationByAppKeyResponse.class);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) {
        LookupApplicationByAppKeyRequest request = new LookupApplicationByAppKeyRequest();
        request.setApplicationKey(applicationKey);
        return this.lookupApplicationByAppKey(request);
    }

    @Override
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) {
        return callV3RestApi("/application/create", request, CreateApplicationResponse.class);
    }

    @Override
    public CreateApplicationResponse createApplication(String name) {
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) {
        return callV3RestApi("/application/version/create", request, CreateApplicationVersionResponse.class);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) {
        CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) {
        return callV3RestApi("/application/version/unsupport", request, UnsupportApplicationVersionResponse.class);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) {
        UnsupportApplicationVersionRequest request = new UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) {
        return callV3RestApi("/application/version/support", request, SupportApplicationVersionResponse.class);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(Long versionId) {
        SupportApplicationVersionRequest request = new SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    @Override
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) {
        return callV3RestApi("/integration/create", request, CreateIntegrationResponse.class);
    }

    @Override
    public CreateIntegrationResponse createIntegration(String name) {
        CreateIntegrationRequest request = new CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    @Override
    public GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) {
        return callV3RestApi("/integration/list", request, GetIntegrationListResponse.class);
    }

    @Override
    public List<GetIntegrationListResponse.Items> getIntegrationList() {
        return this.getIntegrationList(new GetIntegrationListRequest()).getItems();
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) {
        return callV3RestApi("/integration/remove", request, RemoveIntegrationResponse.class);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(String id) {
        RemoveIntegrationRequest request = new RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) {
        return callV3RestApi("/application/callback/create", request, CreateCallbackUrlResponse.class);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl) {
        CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        return this.createCallbackUrl(request);
    }

    @Override
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) {
        return callV3RestApi("/application/callback/list", request, GetCallbackUrlListResponse.class);
    }

    @Override
    public List<GetCallbackUrlListResponse.CallbackUrlList> getCallbackUrlList(Long applicationId) {
        GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return getCallbackUrlList(request).getCallbackUrlList();
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) {
        return callV3RestApi("/application/callback/remove", request, RemoveCallbackUrlResponse.class);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) {
        RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }

    @Override
    public CreateTokenResponse createToken(CreateTokenRequest request) {
        return callV3RestApi("/token/create", request, CreateTokenResponse.class);
    }

    @Override
    public CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                           String encryptedData, String mac, String nonce, SignatureType signatureType) {
        CreateTokenRequest request = new CreateTokenRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setNonce(nonce);
        request.setSignatureType(signatureType);
        return createToken(request);
    }

    @Override
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) {
        return callV3RestApi("/token/validate", request, ValidateTokenResponse.class);
    }

    @Override
    public ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setTokenDigest(tokenDigest);
        return validateToken(request);
    }

    @Override
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) {
        return callV3RestApi("/token/remove", request, RemoveTokenResponse.class);
    }

    @Override
    public RemoveTokenResponse removeToken(String tokenId, String activationId) {
        RemoveTokenRequest request = new RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) {
        return callV3RestApi("/ecies/decryptor", request, GetEciesDecryptorResponse.class);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) {
        GetEciesDecryptorRequest request = new GetEciesDecryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        return getEciesDecryptor(request);
    }

    @Override
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) {
        return callV3RestApi("/upgrade/start", request, StartUpgradeResponse.class);
    }

    @Override
    public StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                             String encryptedData, String mac, String nonce) {
        StartUpgradeRequest request = new StartUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return startUpgrade(request);
    }

    @Override
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) {
        return callV3RestApi("/upgrade/commit", request, CommitUpgradeResponse.class);
    }

    @Override
    public CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) {
        CommitUpgradeRequest request = new CommitUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        return commitUpgrade(request);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) {
        return callV3RestApi("/recovery/create", request, CreateRecoveryCodeResponse.class);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount) {
        CreateRecoveryCodeRequest request = new CreateRecoveryCodeRequest();
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setPukCount(pukCount);
        return createRecoveryCode(request);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) {
        return callV3RestApi("/recovery/confirm", request, ConfirmRecoveryCodeResponse.class);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                           String encryptedData, String mac, String nonce) {
        ConfirmRecoveryCodeRequest request = new ConfirmRecoveryCodeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return confirmRecoveryCode(request);
    }

    @Override
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) {
        return callV3RestApi("/recovery/lookup", request, LookupRecoveryCodesResponse.class);
    }

    @Override
    public LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                           RecoveryCodeStatus recoveryCodeStatus, RecoveryPukStatus recoveryPukStatus) {
        LookupRecoveryCodesRequest request = new LookupRecoveryCodesRequest();
        request.setUserId(userId);
        request.setActivationId(activationId);
        request.setApplicationId(applicationId);
        request.setRecoveryCodeStatus(recoveryCodeStatus);
        request.setRecoveryPukStatus(recoveryPukStatus);
        return lookupRecoveryCodes(request);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) {
        return callV3RestApi("/recovery/revoke", request, RevokeRecoveryCodesResponse.class);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) {
        RevokeRecoveryCodesRequest request = new RevokeRecoveryCodesRequest();
        request.getRecoveryCodeIds().addAll(recoveryCodeIds);
        return revokeRecoveryCodes(request);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) {
        return callV3RestApi("/activation/recovery/create", request, RecoveryCodeActivationResponse.class);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                            String ephemeralPublicKey, String encryptedData, String mac, String nonce) {
        RecoveryCodeActivationRequest request = new RecoveryCodeActivationRequest();
        request.setRecoveryCode(recoveryCode);
        request.setPuk(puk);
        request.setApplicationKey(applicationKey);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return createActivationUsingRecoveryCode(request);
    }

    @Override
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) {
        return callV3RestApi("/recovery/config/detail", request, GetRecoveryConfigResponse.class);
    }

    @Override
    public GetRecoveryConfigResponse getRecoveryConfig(Long applicationId) {
        GetRecoveryConfigRequest request = new GetRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        return getRecoveryConfig(request);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) {
        return callV3RestApi("/recovery/config/update", request, UpdateRecoveryConfigResponse.class);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) {
        UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        request.setActivationRecoveryEnabled(activationRecoveryEnabled);
        request.setRecoveryPostcardEnabled(recoveryPostcardEnabled);
        request.setAllowMultipleRecoveryCodes(allowMultipleRecoveryCodes);
        request.setRemotePostcardPublicKey(remoteRecoveryPublicKeyBase64);
        return updateRecoveryConfig(request);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) {
        return callV3RestApi("/activation/flags/list", request, ListActivationFlagsResponse.class);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(String activationId) {
        ListActivationFlagsRequest request = new ListActivationFlagsRequest();
        request.setActivationId(activationId);
        return listActivationFlags(request);
    }

    @Override
    public CreateActivationFlagsResponse createActivationFlags(CreateActivationFlagsRequest request) {
        return callV3RestApi("/activation/flags/create", request, CreateActivationFlagsResponse.class);
    }

    @Override
    public CreateActivationFlagsResponse createActivationFlags(String activationId, List<String> activationFlags) {
        CreateActivationFlagsRequest request = new CreateActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return createActivationFlags(request);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) {
        return callV3RestApi("/activation/flags/update", request, UpdateActivationFlagsResponse.class);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) {
        UpdateActivationFlagsRequest request = new UpdateActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return updateActivationFlags(request);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) {
        return callV3RestApi("/activation/flags/remove", request, RemoveActivationFlagsResponse.class);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) {
        RemoveActivationFlagsRequest request = new RemoveActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return removeActivationFlags(request);
    }

    @Override
    public PowerAuthClientV2 v2() {
        return new PowerAuthServiceClientV2();
    }

    /**
     * Client with PowerAuth version 2.0 methods. This client will be deprecated in future release.
     */
    public class PowerAuthServiceClientV2 implements PowerAuthClientV2 {

        private static final String PA_REST_V2_PREFIX = "/v2";

        /**
         * Call the PowerAuth v2 API.
         *
         * @param path Path of the endpoint.
         * @param request Request object.
         * @param responseType Response type.
         * @return Response.
         */
        private <T> T callV2RestApi(String path, Object request, Class<T> responseType) {
            ObjectRequest<?> objectRequest = new ObjectRequest<>(request);
            ParameterizedTypeReference<ObjectResponse<T>> typeReference = new ParameterizedTypeReference<ObjectResponse<T>>(){
                @Override
                public Type getType() {
                    return TypeFactory.defaultInstance().constructParametricType(ObjectResponse.class, responseType);
                }
            };
            ObjectResponse<T> objectResponse = webClient.post()
                    .uri(PA_REST_V2_PREFIX + path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(objectRequest))
                    .retrieve()
                    .bodyToMono(typeReference)
                    .block();
            if (objectResponse == null) {
                return null;
            }
            return objectResponse.getResponseObject();
        }

        @Override
        public com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(com.wultra.security.powerauth.client.v2.PrepareActivationRequest request) {
            return callV2RestApi("/activation/prepare", request, com.wultra.security.powerauth.client.v2.PrepareActivationResponse.class);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) {
            com.wultra.security.powerauth.client.v2.PrepareActivationRequest request = new com.wultra.security.powerauth.client.v2.PrepareActivationRequest();
            request.setActivationIdShort(activationIdShort);
            request.setActivationName(activationName);
            request.setActivationNonce(activationNonce);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setEncryptedDevicePublicKey(cDevicePublicKey);
            request.setExtras(extras);
            request.setApplicationKey(applicationKey);
            request.setApplicationSignature(applicationSignature);
            return this.prepareActivation(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(com.wultra.security.powerauth.client.v2.CreateActivationRequest request) {
            return callV2RestApi("/activation/create", request, com.wultra.security.powerauth.client.v2.CreateActivationResponse.class);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) {
            return this.createActivation(
                    applicationKey,
                    userId,
                    null,
                    null,
                    identity,
                    "00000-00000",
                    activationName,
                    activationNonce,
                    ephemeralPublicKey,
                    cDevicePublicKey,
                    extras,
                    applicationSignature
            );
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) {
            com.wultra.security.powerauth.client.v2.CreateActivationRequest request = new com.wultra.security.powerauth.client.v2.CreateActivationRequest();
            request.setApplicationKey(applicationKey);
            request.setUserId(userId);
            if (maxFailureCount != null) {
                request.setMaxFailureCount(maxFailureCount);
            }
            if (timestampActivationExpire != null) {
                request.setTimestampActivationExpire(calendarWithDate(timestampActivationExpire));
            }
            request.setIdentity(identity);
            request.setActivationOtp(activationOtp);
            request.setActivationName(activationName);
            request.setActivationNonce(activationNonce);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setEncryptedDevicePublicKey(cDevicePublicKey);
            request.setExtras(extras);
            request.setApplicationSignature(applicationSignature);
            return this.createActivation(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(com.wultra.security.powerauth.client.v2.VaultUnlockRequest request) {
            return callV2RestApi("/vault/unlock", request, com.wultra.security.powerauth.client.v2.VaultUnlockResponse.class);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, com.wultra.security.powerauth.client.v2.SignatureType signatureType, String reason) {
            com.wultra.security.powerauth.client.v2.VaultUnlockRequest request = new com.wultra.security.powerauth.client.v2.VaultUnlockRequest();
            request.setActivationId(activationId);
            request.setApplicationKey(applicationKey);
            request.setData(data);
            request.setSignature(signature);
            request.setSignatureType(signatureType);
            request.setReason(reason);
            return this.unlockVault(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest request) {
            return callV2RestApi("/activation/encryption/key/create", request, com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse.class);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) {
            com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest request = new com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest();
            request.setActivationId(activationId);
            request.setSessionIndex(sessionIndex);
            return this.generatePersonalizedE2EEncryptionKey(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest request) {
            return callV2RestApi("/application/encryption/key/create", request, com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse.class);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) {
            com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest request = new com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest();
            request.setApplicationKey(applicationKey);
            request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
            request.setSessionIndex(sessionIndex);
            return this.generateNonPersonalizedE2EEncryptionKey(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(com.wultra.security.powerauth.client.v2.CreateTokenRequest request) {
            return callV2RestApi("/token/create", request, com.wultra.security.powerauth.client.v2.CreateTokenResponse.class);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, com.wultra.security.powerauth.client.v2.SignatureType signatureType) {
            com.wultra.security.powerauth.client.v2.CreateTokenRequest request = new com.wultra.security.powerauth.client.v2.CreateTokenRequest();
            request.setActivationId(activationId);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setSignatureType(signatureType);
            return createToken(request);
        }
    }

}
