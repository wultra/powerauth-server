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
package com.wultra.security.powerauth.client.v4;

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v4.*;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.util.Date;
import java.util.List;

/**
 * PowerAuth client interface (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface PowerAuthClient {

    /**
     * Call the getSystemStatus method of the PowerAuth Server interface.
     *
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth Server interface.
     *
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetSystemStatusResponse getSystemStatus(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the getErrorList method of the PowerAuth Server interface.
     *
     * @param request {@link GetErrorCodeListRequest} instance
     * @return {@link GetErrorCodeListResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException;

    /**
     * Call the getErrorList method of the PowerAuth Server interface.
     *
     * @param request {@link GetErrorCodeListRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link GetErrorCodeListResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth Server interface.
     *
     * @param language ISO code for language.
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetErrorCodeListResponse getErrorList(String language) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth Server interface.
     *
     * @param request {@link InitActivationRequest} instance
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(InitActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth Server interface.
     *
     * @param request {@link InitActivationRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(InitActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, String applicationId) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param commitPhase   Specifies when the activation is committed.
     * @param otp           Additional OTP value.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, String applicationId, CommitPhase commitPhase, String otp) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth Server interface.
     *
     * @param userId                    User ID for which a new CREATED activation should be created.
     * @param applicationId             Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount           How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, String applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException;

   /**
     * Call the prepareActivation method of the PowerAuth Server interface.
     *
     * @param request {@link PrepareActivationRequest} instance
     * @return {@link PrepareActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the prepareActivation method of the PowerAuth Server interface.
     *
     * @param request {@link PrepareActivationRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link PrepareActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth Server
     * interface.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateActivationResponse createActivation(CreateActivationRequest request) throws PowerAuthClientException;

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth Server
     * interface.
     *
     * @param request Create activation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Create activation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateActivationResponse createActivation(CreateActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Update the activation name directly, using the updateActivationName method of the PowerAuth Server interface.
     *
     * @param request Update activation name request.
     * @return Update activation name response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationNameResponse updateActivationName(UpdateActivationNameRequest request) throws PowerAuthClientException;

    /**
     * Update the activation name directly, using the updateActivationName method of the PowerAuth Server interface.
     *
     * @param request Update activation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Update activation name response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationNameResponse updateActivationName(UpdateActivationNameRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param request {@link UpdateActivationOtpRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link UpdateActivationOtpResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param request {@link UpdateActivationOtpRequest} instance
     * @return {@link UpdateActivationOtpResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException;

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param activationId   Activation ID for activation to be updated.
     * @param externalUserId User ID of user who updated the activation. Use null value if activation owner caused the change,
     *                       or if OTP value is automatically generated.
     * @param activationOtp  Value of activation OTP
     * @return {@link UpdateActivationOtpResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth Server interface.
     *
     * @param request {@link CommitActivationRequest} instance
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(CommitActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth Server interface.
     *
     * @param request {@link CommitActivationRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(CommitActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @param activationOtp  Value of activation OTP. Specify the value only when activation OTP should be validated during activation commit.
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException;

    /**
     * Call the confirmActivation method of the PowerAuth Server interface.
     *
     * @param request {@link CommitActivationRequest} instance
     * @return {@link Response}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response confirmActivation(ConfirmActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the confirmActivation method of the PowerAuth Server interface.
     *
     * @param request {@link ConfirmActivationRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link Response}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response confirmActivation(ConfirmActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the confirmActivation method of the PowerAuth Server interface.
     *
     * @param activationId   Activation ID for activation to be confirmed.
     * @return {@link Response}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response confirmActivation(String activationId) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth Server interface.
     *
     * @param request {@link GetActivationStatusRequest} instance
     * @return {@link GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth Server interface.
     *
     * @param request {@link GetActivationStatusRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth Server interface.
     *
     * @param activationId Activation identifier to lookup information for.
     * @return {@link GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth Server interface.
     *
     * @param request {@link RemoveActivationRequest} instance.
     * @return {@link RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth Server interface.
     *
     * @param request {@link RemoveActivationRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationResponse removeActivation(RemoveActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth Server interface.
     *
     * @param activationId   Activation ID of activation to be removed.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @return {@link RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth Server interface.
     *
     * @param request {@link GetActivationListForUserRequest} instance
     * @return {@link GetActivationListForUserResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth Server interface.
     *
     * @param request {@link GetActivationListForUserRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link GetActivationListForUserResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth Server interface.
     * This method will fetch the first page (page 0) of activations for the user, with a page size of 100.
     *
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user. Returns the first 100 activations.
     * @throws PowerAuthClientException In case the REST API call fails.
     */
    List<Activation> getActivationListForUser(String userId) throws PowerAuthClientException;

    /**
     * Call the lookupActivations method of the PowerAuth Server interface.
     *
     * @param request {@link LookupActivationsRequest} instance
     * @return {@link LookupActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws PowerAuthClientException;

    /**
     * Call the lookupActivations method of the PowerAuth Server interface.
     *
     * @param request {@link LookupActivationsRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link LookupActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupActivationsResponse lookupActivations(LookupActivationsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the lookupActivations method of the PowerAuth Server interface.
     *
     * @param userIds                 User IDs to be used in the activations query.
     * @param applicationIds          Application IDs to be used in the activations query (optional).
     * @param timestampLastUsedBefore Last used timestamp to be used in the activations query, return all records where timestampLastUsed &lt; timestampLastUsedBefore (optional).
     * @param timestampLastUsedAfter  Last used timestamp to be used in the activations query, return all records where timestampLastUsed &gt;= timestampLastUsedAfter (optional).
     * @param activationStatus        Activation status to be used in the activations query (optional).
     * @param activationFlags         Activation flags (optional).
     * @return List of activation instances satisfying given query parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<Activation> lookupActivations(List<String> userIds, List<String> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth Server interface.
     *
     * @param request {@link UpdateStatusForActivationsRequest} instance
     * @return {@link UpdateStatusForActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth Server interface.
     *
     * @param request {@link UpdateStatusForActivationsRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link UpdateStatusForActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth Server interface.
     *
     * @param activationIds    Identifiers of activations whose status should be updated.
     * @param activationStatus Activation status to be used.
     * @return Response indicating whether activation status update succeeded.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) throws PowerAuthClientException;

    /**
     * Call the verifyAuth method of the PowerAuth Server interface.
     *
     * @param request {@link VerifyAuthenticationRequest} instance.
     * @return {@link VerifyAuthenticationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyAuthenticationResponse verifyAuthentication(VerifyAuthenticationRequest request) throws PowerAuthClientException;

    /**
     * Call the verifyAuth method of the PowerAuth Server interface.
     *
     * @param request {@link VerifyAuthenticationRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link VerifyAuthenticationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyAuthenticationResponse verifyAuthentication(VerifyAuthenticationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the verifyAuth method of the PowerAuth Server interface.
     *
     * @param activationId                Activation ID of activation to be used for authentication.
     * @param applicationKey              Application Key of an application related to the activation.
     * @param data                        Data to be signed encoded in format as specified by PowerAuth data normalization.
     * @param authenticationCode          Request authentication code.
     * @param authenticationCodeType      Request authentication code type.
     * @param authenticationVersion       Authentication version.
     * @param forcedAuthenticationVersion Forced authentication version.
     * @return Verify authentication and return REST response with the verification results.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyAuthenticationResponse verifyAuthentication(String activationId, String applicationKey, String data, String authenticationCode, AuthenticationCodeType authenticationCodeType, String authenticationVersion, Integer forcedAuthenticationVersion) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineAuthPayload method of the PowerAuth Server interface.
     *
     * @param request {@link CreatePersonalizedOfflineAuthPayloadRequest} instance.
     * @return {@link CreatePersonalizedOfflineAuthPayloadRequest}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(CreatePersonalizedOfflineAuthPayloadRequest request) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineAuthPayload method of the PowerAuth Server interface.
     *
     * @param request {@link CreatePersonalizedOfflineAuthPayloadRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link CreatePersonalizedOfflineAuthPayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(CreatePersonalizedOfflineAuthPayloadRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineAuthPayload method of the PowerAuth Server interface.
     *
     * @param activationId Activation ID.
     * @param data         Data for offline authentication.
     * @return {@link CreatePersonalizedOfflineAuthPayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(String activationId, String data) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineAuthPayload method of the PowerAuth Server interface.
     *
     * @param request {@link CreateNonPersonalizedOfflineAuthPayloadRequest} instance.
     * @return {@link CreateNonPersonalizedOfflineAuthPayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(CreateNonPersonalizedOfflineAuthPayloadRequest request) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineAuthPayload method of the PowerAuth Server interface.
     *
     * @param request {@link CreateNonPersonalizedOfflineAuthPayloadRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link CreateNonPersonalizedOfflineAuthPayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(CreateNonPersonalizedOfflineAuthPayloadRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineAuthPayload method of the PowerAuth Server interface.
     *
     * @param applicationId Application ID.
     * @param data          Data for offline authentication.
     * @return {@link CreateNonPersonalizedOfflineAuthPayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(String applicationId, String data) throws PowerAuthClientException;

    /**
     * Verify offline authentication by calling verifyOfflineAuth method of the PowerAuth Server interface.
     *
     * @param request {@link VerifyOfflineAuthenticationRequest} instance.
     * @return {@link VerifyOfflineAuthenticationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(VerifyOfflineAuthenticationRequest request) throws PowerAuthClientException;

    /**
     * Verify offline authentication by calling verifyOfflineAuth method of the PowerAuth Server interface.
     *
     * @param request {@link VerifyOfflineAuthenticationRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link VerifyOfflineAuthenticationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(VerifyOfflineAuthenticationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Verify offline authentication by calling verifyOfflineAuth method of the PowerAuth Server interface.
     *
     * @param activationId       Activation ID.
     * @param data               Data for authentication.
     * @param authenticationCode Authentication code value.
     * @param allowBiometry      Whether POSSESSION_BIOMETRY authentication code type is allowed during authentication.
     * @return Offline authentication verification response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(String activationId, String data, String authenticationCode, boolean allowBiometry) throws PowerAuthClientException;

    /**
     * Call the vaultUnlock method of the PowerAuth Server interface.
     *
     * @param request {@link VaultUnlockRequest} instance
     * @return {@link VaultUnlockResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException;

    /**
     * Call the vaultUnlock method of the PowerAuth Server interface.
     *
     * @param request {@link VaultUnlockRequest} instance
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link VaultUnlockResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VaultUnlockResponse unlockVault(VaultUnlockRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the verifyAsymmetricSignature method of the PowerAuth Server interface.
     *
     * @param request {@link VerifyAsymmetricSignatureRequest} instance.
     * @return {@link VerifyAsymmetricSignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyAsymmetricSignatureResponse verifyAsymmetricSignature(VerifyAsymmetricSignatureRequest request) throws PowerAuthClientException;

    /**
     * Call the verifyAsymmetricSignature method of the PowerAuth Server interface.
     *
     * @param request {@link VerifyAsymmetricSignatureRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link VerifyAsymmetricSignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyAsymmetricSignatureResponse verifyAsymmetricSignature(VerifyAsymmetricSignatureRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the verifyAsymmetricSignature method of the PowerAuth Server interface.
     *
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data         Data that were signed by asymmetric signature algorithm.
     * @param signature    Request signature.
     * @return Verify asymmetric signature and return REST response with the verification results.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyAsymmetricSignatureResponse verifyAsymmetricSignature(String activationId, String data, String signature) throws PowerAuthClientException;

    /**
     * Call the getSignatureAuditLog method of the PowerAuth Server interface.
     *
     * @param request {@link SignatureAuditRequest} instance.
     * @return {@link SignatureAuditResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException;

    /**
     * Call the getSignatureAuditLog method of the PowerAuth Server interface.
     *
     * @param request {@link SignatureAuditRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link SignatureAuditResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth Server interface and get
     * signature audit log for all application of a given user.
     *
     * @param userId       User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link SignatureAuditItem}.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<SignatureAuditItem> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth Server interface and get
     * signature audit log for a single application.
     *
     * @param userId        User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate  Limit the results to given starting date (= "newer than").
     * @param endingDate    Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link SignatureAuditItem}.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<SignatureAuditItem> getSignatureAuditLog(String userId, String applicationId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth Server interface.
     *
     * @param request {@link ActivationHistoryRequest} instance.
     * @return {@link ActivationHistoryResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth Server interface.
     *
     * @param request {@link ActivationHistoryRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link ActivationHistoryResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth Server interface.
     *
     * @param activationId Activation ID.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of activation history items. See: {@link ActivationHistoryItem}.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<ActivationHistoryItem> getActivationHistory(String activationId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth Server interface.
     *
     * @param request {@link BlockActivationRequest} instance.
     * @return {@link BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    BlockActivationResponse blockActivation(BlockActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth Server interface.
     *
     * @param request {@link BlockActivationRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    BlockActivationResponse blockActivation(BlockActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth Server interface.
     *
     * @param activationId   Activation ID of activation to be blocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @param reason         Reason why activation is being blocked.
     * @return {@link BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth Server interface.
     *
     * @param request {@link UnblockActivationRequest} instance.
     * @return {@link UnblockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth Server interface.
     *
     * @param request {@link UnblockActivationRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link UnblockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnblockActivationResponse unblockActivation(UnblockActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth Server interface.
     *
     * @param activationId   Activation ID of activation to be unblocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @return {@link UnblockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnblockActivationResponse unblockActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @return {@link GetApplicationListResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationListResponse getApplicationList() throws PowerAuthClientException;

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link GetApplicationListResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationListResponse getApplicationList(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Return the detail of given application, including all application versions.
     *
     * @param request {@link GetApplicationDetailRequest} instance.
     * @return {@link GetApplicationDetailResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException;

    /**
     * Return the detail of given application, including all application versions.
     *
     * @param request {@link GetApplicationDetailRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link GetApplicationDetailResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Get the detail of an application with given ID, including the version list.
     *
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationDetailResponse getApplicationDetail(String applicationId) throws PowerAuthClientException;

    /**
     * Lookup an application by application key.
     *
     * @param request {@link LookupApplicationByAppKeyRequest} instance.
     * @return {@link LookupApplicationByAppKeyResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws PowerAuthClientException;

    /**
     * Lookup an application by application key.
     *
     * @param request {@link LookupApplicationByAppKeyRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link LookupApplicationByAppKeyResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Lookup an application by application key.
     *
     * @param applicationKey Application key.
     * @return Response with application ID.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) throws PowerAuthClientException;

    /**
     * Create a new application with given name.
     *
     * @param request {@link CreateApplicationRequest} instance.
     * @return {@link CreateApplicationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationResponse createApplication(CreateApplicationRequest request) throws PowerAuthClientException;

    /**
     * Create a new application with given name.
     *
     * @param request {@link CreateApplicationRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link CreateApplicationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationResponse createApplication(CreateApplicationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create a new application with given name.
     *
     * @param name Name of the new application.
     * @return Application with a given name.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationResponse createApplication(String name) throws PowerAuthClientException;

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param request {@link CreateApplicationVersionRequest} instance.
     * @return {@link CreateApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws PowerAuthClientException;

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param request {@link CreateApplicationVersionRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link CreateApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param applicationId ID of an application to create a version for.
     * @param versionName   Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationVersionResponse createApplicationVersion(String applicationId, String versionName) throws PowerAuthClientException;

    /**
     * Cancel the support for a given application version.
     *
     * @param request {@link UnsupportApplicationVersionRequest} instance.
     * @return {@link UnsupportApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws PowerAuthClientException;

    /**
     * Cancel the support for a given application version.
     *
     * @param request {@link UnsupportApplicationVersionRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link UnsupportApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Cancel the support for a given application version.
     *
     * @param appId Application ID.
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(String appId, String versionId) throws PowerAuthClientException;

    /**
     * Renew the support for a given application version.
     *
     * @param request {@link SupportApplicationVersionRequest} instance.
     * @return {@link SupportApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws PowerAuthClientException;

    /**
     * Renew the support for a given application version.
     *
     * @param request {@link SupportApplicationVersionRequest} instance.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return {@link SupportApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Renew the support for a given application version.
     *
     * @param appId Application ID.
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SupportApplicationVersionResponse supportApplicationVersion(String appId, String versionId) throws PowerAuthClientException;

    /**
     * Create a new integration with given name.
     *
     * @param request Request specifying the integration name.
     * @return New integration information.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws PowerAuthClientException;

    /**
     * Create a new integration with given name.
     *
     * @param request Request specifying the integration name.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return New integration information.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateIntegrationResponse createIntegration(CreateIntegrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create a new integration with given name.
     *
     * @param name Integration name.
     * @return New integration information.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateIntegrationResponse createIntegration(String name) throws PowerAuthClientException;

    /**
     * Get the list of integrations.
     *
     * @return List of integrations.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetIntegrationListResponse getIntegrationList() throws PowerAuthClientException;

    /**
     * Get the list of integrations.
     *
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return List of integrations.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetIntegrationListResponse getIntegrationList(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove integration with given ID.
     *
     * @param request REST object with integration ID to be removed.
     * @return Removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws PowerAuthClientException;

    /**
     * Remove integration with given ID.
     *
     * @param request REST object with integration ID to be removed.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove integration with given ID.
     *
     * @param id ID of integration to be removed.
     * @return Removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveIntegrationResponse removeIntegration(String id) throws PowerAuthClientException;

    /**
     * Create a new callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Create a new callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create a new callback URL with given parameters.
     *
     * @param applicationId   Application ID.
     * @param name            Callback URL display name.
     * @param type            Callback type.
     * @param callbackUrl     Callback URL value.
     * @param attributes      Attributes to send in the callback data.
     * @param authentication  Callback request authentication.
     * @param retentionPeriod Duration after which a completed callback event is automatically removed.
     * @param initialBackoff  Initial delay before retry attempt following a callback event failure.
     * @param maxAttempts     Maximum number of attempts to send a callback event.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateCallbackUrlResponse createCallbackUrl(String applicationId, String name, CallbackUrlType type, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication, Duration retentionPeriod, Duration initialBackoff, Integer maxAttempts) throws PowerAuthClientException;

    /**
     * Update a callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Update a callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Update a callback URL with given parameters.
     *
     * @param id              Callback URL identifier.
     * @param applicationId   Application ID.
     * @param name            Callback URL display name.
     * @param type            Callback type.
     * @param callbackUrl     Callback URL value.
     * @param attributes      Attributes to send in the callback data.
     * @param authentication  Callback request authentication.
     * @param retentionPeriod Duration after which a completed callback event is automatically removed.
     * @param initialBackoff  Initial delay before retry attempt following a callback event failure.
     * @param maxAttempts     Maximum number of attempts to send a callback event.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateCallbackUrlResponse updateCallbackUrl(String id, String applicationId, String name, CallbackUrlType type, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication, Duration retentionPeriod, Duration initialBackoff, Integer maxAttempts) throws PowerAuthClientException;

    /**
     * Get the response with list of callback URL objects.
     *
     * @param applicationId ID of the application.
     * @return Response with the list of all callback URLs for given application.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetCallbackUrlListResponse getCallbackUrlList(String applicationId) throws PowerAuthClientException;

    /**
     * Get the response with list of callback URL objects.
     *
     * @param request REST request object with application ID.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Response with the list of all callback URLs for given application.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;


    /**
     * Remove callback URL.
     *
     * @param request Remove callback URL request.
     * @return Information about removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Remove callback URL.
     *
     * @param request Remove callback URL request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Information about removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove callback URL.
     *
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws PowerAuthClientException;

    /**
     * Create a new token for basic token-based authentication.
     *
     * @param request Request with token information.
     * @return Response with created token.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateTokenResponse createToken(CreateTokenRequest request) throws PowerAuthClientException;

    /**
     * Create a new token for basic token-based authentication.
     *
     * @param request Request with token information.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Response with created token.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateTokenResponse createToken(CreateTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Validate credentials used for basic token-based authentication.
     *
     * @param request Credentials to validate.
     * @return Response with the credentials validation status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ValidateTokenResponse validateToken(ValidateTokenRequest request) throws PowerAuthClientException;

    /**
     * Validate credentials used for basic token-based authentication.
     *
     * @param request Credentials to validate.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Response with the credentials validation status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ValidateTokenResponse validateToken(ValidateTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Validate credentials used for basic token-based authentication.
     *
     * @param tokenId         Token ID.
     * @param nonce           Random token nonce.
     * @param protocolVersion Cryptography protocol version.
     * @param timestamp       Token timestamp.
     * @param tokenDigest     Token digest.
     * @return Response with the credentials validation status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ValidateTokenResponse validateToken(String tokenId, String nonce, String protocolVersion, long timestamp, String tokenDigest) throws PowerAuthClientException;

    /**
     * Remove token with given token ID.
     *
     * @param request Request with token ID.
     * @return Response token removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveTokenResponse removeToken(RemoveTokenRequest request) throws PowerAuthClientException;

    /**
     * Remove token with given token ID.
     *
     * @param request Request with token ID.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Response token removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveTokenResponse removeToken(RemoveTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove token with given token ID.
     *
     * @param tokenId      Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException;

    /**
     * Extract AEAD encryptor parameters.
     *
     * @param request Request for AEAD encryptor extraction.
     * @return AEAD encryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ExtractEncryptorResponse extractEncryptor(ExtractEncryptorRequest request) throws PowerAuthClientException;

    /**
     * Extract AEAD encryptor parameters.
     *
     * @param request Request for AEAD encryptor extraction.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return AEAD encryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ExtractEncryptorResponse extractEncryptor(ExtractEncryptorRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Extract AEAD encryptor parameters.
     *
     * @param activationId       Activation ID.
     * @param applicationKey     Application key.
     * @param nonce              Nonce.
     * @param protocolVersion    Crypto protocol version.
     * @param timestamp          Unix timestamp in milliseconds.
     * @param temporaryKeyId     Temporary Key ID.
     * @return AEAD encryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ExtractEncryptorResponse extractEncryptor(String activationId, String applicationKey,
                                              String nonce, String protocolVersion, Long timestamp,
                                              String temporaryKeyId) throws PowerAuthClientException;

    /**
     * Start upgrade of activations to version 3.
     *
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws PowerAuthClientException;

    /**
     * Start upgrade of activations to version 3.
     *
     * @param request Start upgrade request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Start upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    StartUpgradeResponse startUpgrade(StartUpgradeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws PowerAuthClientException;

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param request Commit upgrade request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Commit upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param activationId   Activation ID.
     * @param applicationKey Application key.
     * @return Commit upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) throws PowerAuthClientException;

    /**
     * List activation flags.
     *
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * List activation flags.
     *
     * @param request List activation flags request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return List activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * List activation flags.
     *
     * @param activationId Activation ID.
     * @return List activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListActivationFlagsResponse listActivationFlags(String activationId) throws PowerAuthClientException;

    /**
     * Add activation flags.
     *
     * @param request Add activation flags request.
     * @return Add activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * Add activation flags.
     *
     * @param request Add activation flags request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Add activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Add activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Add activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddActivationFlagsResponse addActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Update activation flags.
     *
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * Update activation flags.
     *
     * @param request Update activation flags request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Update activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Update activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Update activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Remove activation flags.
     *
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * Remove activation flags.
     *
     * @param request Remove activation flags request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Remove activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Remove activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * List application roles.
     * @param request List application roles request.
     * @return List application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * List application roles.
     * @param request List application roles request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return List application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * List application roles.
     * @param applicationId Application ID.
     * @return List application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListApplicationRolesResponse listApplicationRoles(String applicationId) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param request Add application roles request.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param request Add application roles request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to add.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddApplicationRolesResponse addApplicationRoles(String applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param request Update application roles request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to set.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateApplicationRolesResponse updateApplicationRoles(String applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param request Remove application roles request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to remove.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveApplicationRolesResponse removeApplicationRoles(String applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Create new operation.
     * @param request Create operation request.
     * @return Create operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse createOperation(OperationCreateRequest request) throws PowerAuthClientException;

    /**
     * Create new operation.
     * @param request Create operation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Create operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse createOperation(OperationCreateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Get operation detail.
     * @param request Operation detail request.
     * @return Operation detail response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationDetail(OperationDetailRequest request) throws PowerAuthClientException;

    /**
     * Get operation detail.
     * @param request Operation detail request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Operation detail response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationDetail(OperationDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Claim operation for a user.
     * @param request Operation detail request.
     * @return Operation detail response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationClaim(OperationClaimRequest request) throws PowerAuthClientException;

    /**
     * Claim operation for a user.
     * @param request Operation detail request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Operation detail response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationClaim(OperationClaimRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Get list with all operations for provided user.
     * @param request Get operation list request.
     * @return Get operation list response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationListResponse operationList(OperationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Get list with all operations for provided user.
     * @param request Get operation list request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Get operation list response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationListResponse operationList(OperationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Get pending operation list.
     * @param request Get pending operation list request.
     * @return Get pending operation list response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationListResponse operationPendingList(OperationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Get pending operation list.
     * @param request Get pending operation list request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Get pending operation list response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationListResponse operationPendingList(OperationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Cancel operation.
     * @param request Cancel operation request.
     * @return Cancel operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationCancel(OperationCancelRequest request) throws PowerAuthClientException;

    /**
     * Cancel operation.
     * @param request Cancel operation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Cancel operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationCancel(OperationCancelRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Approve operation.
     * @param request Approve operation request.
     * @return Approve operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse operationApprove(OperationApproveRequest request) throws PowerAuthClientException;

    /**
     * Approve operation.
     * @param request Approve operation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Approve operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse operationApprove(OperationApproveRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Simulate approval failure. Useful when you need to enforce decrement of a counter,
     * or eventual operation failure.
     * @param request Failed approval operation request.
     * @return Failed approval operation request.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws PowerAuthClientException;

    /**
     * Simulate approval failure. Useful when you need to enforce decrement of a counter,
     * or eventual operation failure.
     * @param request Failed approval operation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Failed approval operation request.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Reject operation.
     * @param request Reject operation request.
     * @return Reject operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse operationReject(OperationRejectRequest request) throws PowerAuthClientException;

    /**
     * Reject operation.
     * @param request Reject operation request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Reject operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse operationReject(OperationRejectRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Get operation template list.
     * @return Operation template list.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateListResponse operationTemplateList() throws PowerAuthClientException;

    /**
     * Get operation template detail.
     * @param request Operation template detail request.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse operationTemplateDetail(OperationTemplateDetailRequest request) throws PowerAuthClientException;

    /**
     * Get operation template detail.
     * @param request Operation template detail request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse operationTemplateDetail(OperationTemplateDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create a new operation template.
     * @param request New operation template details.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) throws PowerAuthClientException;

    /**
     * Create a new operation template.
     * @param request New operation template details.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Update an operation template.
     * @param request Updated operation template details.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) throws PowerAuthClientException;

    /**
     * Update an operation template.
     * @param request Updated operation template details.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove operation template.
     * @param request Remove operation template request.
     * @return Plain response object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeOperationTemplate(OperationTemplateDeleteRequest request) throws PowerAuthClientException;

    /**
     * Remove operation template.
     * @param request Remove operation template request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Plain response object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeOperationTemplate(OperationTemplateDeleteRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Request telemetry report.
     * @param request Report specification.
     * @return Report data.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    TelemetryReportResponse requestTelemetryReport(TelemetryReportRequest request) throws PowerAuthClientException;

    /**
     * Request telemetry report.
     * @param request Report specification.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Report data.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    TelemetryReportResponse requestTelemetryReport(TelemetryReportRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create an application configuration.
     * @param request Create application configuration request.
     * @return Create application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationConfigResponse createApplicationConfig(CreateApplicationConfigRequest request) throws PowerAuthClientException;

    /**
     * Create an application configuration.
     * @param request Create application configuration request.
     * @return Create application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationConfigResponse createApplicationConfig(CreateApplicationConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Create an application configuration.
     * @param applicationId Application identifier.
     * @param key Configuration key.
     * @param values Configuration values.
     * @return Create application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationConfigResponse createApplicationConfig(String applicationId, String key, List<Object> values) throws PowerAuthClientException;

    /**
     * Remove an application configuration record.
     * @param request Remove application configuration request.
     * @return Remove application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeApplicationConfig(RemoveApplicationConfigRequest request) throws PowerAuthClientException;

    /**
     * Remove an application configuration record.
     * @param request Remove application configuration request.
     * @return Remove application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeApplicationConfig(RemoveApplicationConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove an application configuration record.
     * @param applicationId Application identifier.
     * @param key Configuration key.
     * @return Response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeApplicationConfig(String applicationId, String key) throws PowerAuthClientException;

    /**
     * Get application configuration.
     * @param request Get application configuration request.
     * @return Application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationConfigResponse getApplicationConfig(GetApplicationConfigRequest request) throws PowerAuthClientException;

    /**
     * Get application configuration.
     * @param request Get application configuration request.
     * @return Application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationConfigResponse getApplicationConfig(GetApplicationConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Get application configuration.
     * @param applicationId Application identifier.
     * @return Application configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationConfigResponse getApplicationConfig(String applicationId) throws PowerAuthClientException;

    /**
     * Fetch a new temporary public key.
     * @param request Requested public key parameters.
     * @param queryParams Query params.
     * @param httpHeaders HTTP headers.
     * @return Requested public key.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    TemporaryPublicKeyResponse fetchTemporaryPublicKey(TemporaryPublicKeyRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove a temporary public key.
     * @param id ID of the temporary public key to remove.
     * @param queryParams Query params.
     * @param httpHeaders HTTP headers.
     * @return Response with removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveTemporaryPublicKeyResponse removeTemporaryPublicKey(String id, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Change the password for the knowledge factor.
     * @param request Change password request.
     * @return Change password response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ChangePasswordResponse changePassword(ChangePasswordRequest request) throws PowerAuthClientException;

    /**
     * Change the password for the knowledge factor.
     * @param request Change password request.
     * @param queryParams Query params.
     * @param httpHeaders HTTP headers.
     * @return Change password response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ChangePasswordResponse changePassword(ChangePasswordRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Set up biometry.
     * @param request Add biometry request.
     * @return Add biometry response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddBiometryResponse addBiometry(AddBiometryRequest request) throws PowerAuthClientException;

    /**
     * Set up biometry.
     * @param request Add biometry request.
     * @param queryParams Query params.
     * @param httpHeaders HTTP headers.
     * @return Add biometry response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddBiometryResponse addBiometry(AddBiometryRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Remove biometry.
     * @param request Remove biometry request.
     * @return Response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeBiometry(RemoveBiometryRequest request) throws PowerAuthClientException;

    /**
     * Remove biometry.
     * @param request Remove biometry request.
     * @param queryParams Query params.
     * @param httpHeaders HTTP headers.
     * @return Response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeBiometry(RemoveBiometryRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

}
