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
package com.wultra.security.powerauth.client;

import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest;
import com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse;
import com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest;
import com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.core.rest.model.base.response.Response;

import java.util.Date;
import java.util.List;

/**
 * PowerAuth client interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface PowerAuthClient {

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetSystemStatusRequest} instance
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetSystemStatusRequest} instance
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param language ISO code for language.
     * @return {@link GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetErrorCodeListResponse getErrorList(String language) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link InitActivationRequest} instance
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(InitActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, Long applicationId) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param otpValidation Mode that determines in which stage of activation should be additional OTP validated.
     * @param otp           Additional OTP value.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, Long applicationId, ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId                    User ID for which a new CREATED activation should be created.
     * @param applicationId             Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount           How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId                    User ID for which a new CREATED activation should be created.
     * @param applicationId             Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount           How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @param otpValidation             Mode that determines in which stage of activation should be additional OTP validated.
     * @param otp                       Additional OTP value.
     * @return {@link InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                          ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException;

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link PrepareActivationRequest} instance
     * @return {@link PrepareActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationCode     Activation code.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @param encryptedData      Encrypted data for ECIES.
     * @param mac                Mac of key and data for ECIES.
     * @param nonce              Nonce for ECIES.
     * @return {@link PrepareActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException;

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
     * Call the createActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId                    User ID.
     * @param timestampActivationExpire Expiration timestamp for activation (optional).
     * @param maxFailureCount           Maximum failure count (optional).
     * @param applicationKey            Application key.
     * @param ephemeralPublicKey        Ephemeral key for ECIES.
     * @param encryptedData             Encrypted data for ECIES.
     * @param mac                       Mac of key and data for ECIES.
     * @param nonce                     Nonce for ECIES.
     * @return {@link CreateActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                              String applicationKey, String ephemeralPublicKey, String encryptedData,
                                              String mac, String nonce) throws PowerAuthClientException;

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
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param request {@link UpdateActivationOtpRequest} instance
     * @return {@link UpdateActivationOtpResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CommitActivationRequest} instance
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(CommitActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @param activationOtp  Value of activation OTP. Specify the value only when activation OTP should be validated during activation commit.
     * @return {@link CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetActivationStatusRequest} instance
     * @return {@link GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface. This method should be used only
     * to acquire the activation status for other, than PowerAuth standard RESTful API purposes. If you're implementing
     * the PowerAuth standard RESTful API, then use {@link #getActivationStatusWithEncryptedStatusBlob(String, String)}
     * method instead.
     *
     * @param activationId Activation Id to lookup information for.
     * @return {@link GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface. The method should be used to
     * acquire the activation status for PowerAuth standard RESTful API implementation purposes. The returned object
     * contains an encrypted activation status blob.
     *
     * @param activationId Activation Id to lookup information for.
     * @param challenge    Cryptographic challenge for activation status blob encryption.
     * @return {@link GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link RemoveActivationRequest} instance.
     * @return {@link RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be removed.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @return {@link RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId        Activation ID of activation to be removed.
     * @param externalUserId      User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @param revokeRecoveryCodes Indicates if the recovery codes associated with this activation should be also revoked.
     * @return {@link RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveActivationResponse removeActivation(String activationId, String externalUserId, Boolean revokeRecoveryCodes) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetActivationListForUserRequest} instance
     * @return {@link GetActivationListForUserResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server interface.
     *
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<GetActivationListForUserResponse.Activations> getActivationListForUser(String userId) throws PowerAuthClientException;

    /**
     * Call the lookupActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link LookupActivationsRequest} instance
     * @return {@link LookupActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws PowerAuthClientException;

    /**
     * Call the lookupActivations method of the PowerAuth 3.0 Server interface.
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
    List<LookupActivationsResponse.Activations> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link UpdateStatusForActivationsRequest} instance
     * @return {@link UpdateStatusForActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param activationIds    Identifiers of activations whose status should be updated.
     * @param activationStatus Activation status to be used.
     * @return Response indicating whether activation status update succeeded.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifySignatureRequest} instance.
     * @return {@link VerifySignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId           Activation ID of activation to be used for authentication.
     * @param applicationKey         Application Key of an application related to the activation.
     * @param data                   Data to be signed encoded in format as specified by PowerAuth data normalization.
     * @param signature              Request signature.
     * @param signatureType          Request signature type.
     * @param signatureVersion       Signature version.
     * @param forcedSignatureVersion Forced signature version.
     * @return Verify signature and return REST response with the verification results.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CreatePersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID.
     * @param data         Data for offline signature.
     * @return {@link CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CreateNonPersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param applicationId Application ID.
     * @param data          Data for offline signature.
     * @return {@link CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) throws PowerAuthClientException;

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifyOfflineSignatureRequest} instance.
     * @return {@link VerifyOfflineSignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws PowerAuthClientException;

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId  Activation ID.
     * @param data          Data for signature.
     * @param signature     Signature value.
     * @param allowBiometry Whether POSSESSION_BIOMETRY signature type is allowed during signature verification.
     * @return Offline signature verification response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) throws PowerAuthClientException;

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VaultUnlockRequest} instance
     * @return {@link VaultUnlockResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException;

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId       Activation Id of an activation to be used for authentication.
     * @param applicationKey     Application Key of an application related to the activation.
     * @param signedData         Data to be signed encoded in format as specified by PowerAuth data normalization.
     * @param signature          Vault opening request signature.
     * @param signatureType      Vault opening request signature type.
     * @param signatureVersion   Signature version.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @param encryptedData      Encrypted data for ECIES.
     * @param mac                MAC of key and data for ECIES.
     * @param nonce              Nonce for ECIES.
     * @return {@link VaultUnlockResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                    SignatureType signatureType, String signatureVersion, String signedData,
                                    String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifyECDSASignatureRequest} instance.
     * @return {@link VerifyECDSASignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws PowerAuthClientException;

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data         Data that were signed by ECDSA algorithm.
     * @param signature    Request signature.
     * @return Verify ECDSA signature and return REST response with the verification results.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws PowerAuthClientException;

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link SignatureAuditRequest} instance.
     * @return {@link SignatureAuditResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface and get
     * signature audit log for all application of a given user.
     *
     * @param userId       User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link com.wultra.security.powerauth.client.v3.SignatureAuditResponse.Items}.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface and get
     * signature audit log for a single application.
     *
     * @param userId        User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate  Limit the results to given starting date (= "newer than").
     * @param endingDate    Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link com.wultra.security.powerauth.client.v3.SignatureAuditResponse.Items}.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link ActivationHistoryRequest} instance.
     * @return {@link ActivationHistoryResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of activation history items. See: {@link com.wultra.security.powerauth.client.v3.ActivationHistoryResponse.Items}.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<ActivationHistoryResponse.Items> getActivationHistory(String activationId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link BlockActivationRequest} instance.
     * @return {@link BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    BlockActivationResponse blockActivation(BlockActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be blocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @param reason         Reason why activation is being blocked.
     * @return {@link BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link UnblockActivationRequest} instance.
     * @return {@link UnblockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server interface.
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
     * @param request {@link GetApplicationListRequest} instance.
     * @return {@link GetApplicationListResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws PowerAuthClientException;

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @return List of applications.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<GetApplicationListResponse.Applications> getApplicationList() throws PowerAuthClientException;

    /**
     * Return the detail of given application, including all application versions.
     *
     * @param request {@link GetApplicationDetailRequest} instance.
     * @return {@link GetApplicationDetailResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException;

    /**
     * Get the detail of an application with given ID, including the version list.
     *
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws PowerAuthClientException;

    /**
     * Get the detail of an application with given name, including the version list.
     *
     * @param applicationName name of an application to fetch.
     * @return Application with given name, including the version list.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetApplicationDetailResponse getApplicationDetail(String applicationName) throws PowerAuthClientException;

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
     * @param applicationId ID of an application to create a version for.
     * @param versionName   Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws PowerAuthClientException;

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
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws PowerAuthClientException;

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
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws PowerAuthClientException;

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
     * @param name Integration name.
     * @return New integration information.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateIntegrationResponse createIntegration(String name) throws PowerAuthClientException;

    /**
     * Get the list of integrations.
     *
     * @param request REST request object.
     * @return List of integrations.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws PowerAuthClientException;

    /**
     * Get the list of integrations.
     *
     * @return List of integrations.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<GetIntegrationListResponse.Items> getIntegrationList() throws PowerAuthClientException;

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
     * Create a new callback URL with given parameters.
     *
     * @param applicationId  Application ID.
     * @param name           Callback URL display name.
     * @param type           Callback type.
     * @param callbackUrl    Callback URL value.
     * @param attributes     Attributes to send in the callback data.
     * @param authentication Callback request authentication.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, CallbackUrlType type, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication) throws PowerAuthClientException;

    /**
     * Update a callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Update a callback URL with given parameters.
     *
     * @param id             Callback URL identifier.
     * @param applicationId  Application ID.
     * @param name           Callback URL display name.
     * @param callbackUrl    Callback URL value.
     * @param attributes     Attributes to send in the callback data.
     * @param authentication Callback request authentication.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateCallbackUrlResponse updateCallbackUrl(String id, long applicationId, String name, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication) throws PowerAuthClientException;

    /**
     * Get the response with list of callback URL objects.
     *
     * @param request REST request object with application ID.
     * @return Response with the list of all callback URLs for given application.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws PowerAuthClientException;

    /**
     * Get the list of callback URL objects.
     *
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<GetCallbackUrlListResponse.CallbackUrlList> getCallbackUrlList(Long applicationId) throws PowerAuthClientException;

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
     * @param activationId       Activation ID for the activation that is associated with the token.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key used for response encryption.
     * @param encryptedData      Encrypted request data.
     * @param mac                MAC computed for request key and data.
     * @param nonce              Nonce for ECIES.
     * @param signatureType      Type of the signature used for validating the create request.
     * @return Response with created token.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                    String encryptedData, String mac, String nonce, SignatureType signatureType) throws PowerAuthClientException;

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
     * @param tokenId     Token ID.
     * @param nonce       Random token nonce.
     * @param timestamp   Token timestamp.
     * @param tokenDigest Token digest.
     * @return Response with the credentials validation status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws PowerAuthClientException;

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
     * @param tokenId      Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException;

    /**
     * Get ECIES decryptor parameters.
     *
     * @param request Request for ECIES decryptor parameters.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws PowerAuthClientException;

    /**
     * Get ECIES decryptor parameters.
     *
     * @param activationId       Activation ID.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthClientException;

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
     * @param activationId       Activation ID.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key used for response encryption.
     * @param encryptedData      Encrypted request data.
     * @param mac                MAC computed for request key and data.
     * @param nonce              Nonce for ECIES.
     * @return Start upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                      String encryptedData, String mac, String nonce) throws PowerAuthClientException;

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
     * @param activationId   Activation ID.
     * @param applicationKey Application key.
     * @return Commit upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) throws PowerAuthClientException;

    /**
     * Create recovery code.
     *
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws PowerAuthClientException;

    /**
     * Create recovery code for user.
     *
     * @param applicationId Application ID.
     * @param userId        User ID.
     * @param pukCount      Number of PUKs to create.
     * @return Create recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount) throws PowerAuthClientException;

    /**
     * Confirm recovery code.
     *
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws PowerAuthClientException;

    /**
     * Confirm recovery code.
     *
     * @param activationId       Activation ID.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @param encryptedData      Encrypted data for ECIES.
     * @param mac                MAC of key and data for ECIES.
     * @param nonce              Nonce for ECIES.
     * @return Confirm recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                    String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Lookup recovery codes.
     *
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws PowerAuthClientException;

    /**
     * Lookup recovery codes.
     *
     * @param userId             User ID.
     * @param activationId       Activation ID.
     * @param applicationId      Application ID.
     * @param recoveryCodeStatus Recovery code status.
     * @param recoveryPukStatus  Recovery PUK status.
     * @return Lookup recovery codes response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                    RecoveryCodeStatus recoveryCodeStatus, RecoveryPukStatus recoveryPukStatus) throws PowerAuthClientException;

    /**
     * Revoke recovery codes.
     *
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws PowerAuthClientException;

    /**
     * Revoke recovery codes.
     *
     * @param recoveryCodeIds Identifiers of recovery codes to revoke.
     * @return Revoke recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) throws PowerAuthClientException;

    /**
     * Create activation using recovery code.
     *
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws PowerAuthClientException;

    /**
     * Create activation using recovery code.
     *
     * @param recoveryCode       Recovery code.
     * @param puk                Recovery PUK.
     * @param applicationKey     Application key.
     * @param maxFailureCount    Maximum failure count.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @param encryptedData      Encrypted data for ECIES.
     * @param mac                MAC of key and data for ECIES.
     * @param nonce              nonce for ECIES.
     * @return Create activation using recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                     String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Get recovery configuration.
     *
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws PowerAuthClientException;

    /**
     * Get recovery configuration.
     *
     * @param applicationId Application ID.
     * @return Get recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    GetRecoveryConfigResponse getRecoveryConfig(Long applicationId) throws PowerAuthClientException;

    /**
     * Update recovery configuration.
     *
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws PowerAuthClientException;

    /**
     * Update recovery configuration.
     *
     * @param applicationId                 Application ID.
     * @param activationRecoveryEnabled     Whether activation recovery is enabled.
     * @param recoveryPostcardEnabled       Whether recovery postcard is enabled.
     * @param allowMultipleRecoveryCodes    Whether multiple recovery codes are allowed.
     * @param remoteRecoveryPublicKeyBase64 Base64 encoded remote key.
     * @return Update recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) throws PowerAuthClientException;

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
     * @param applicationId Application ID.
     * @return List application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    ListApplicationRolesResponse listApplicationRoles(Long applicationId) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param request Add application roles request.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to add.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AddApplicationRolesResponse addApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to set.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    UpdateApplicationRolesResponse updateApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to remove.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    RemoveApplicationRolesResponse removeApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Create new operation.
     * @param request Create operation request.
     * @return Create operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse createOperation(OperationCreateRequest request) throws PowerAuthClientException;

    /**
     * Get operation detail.
     * @param request Operation detail request.
     * @return Operation detail response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationDetail(OperationDetailRequest request) throws PowerAuthClientException;

    /**
     * Get list with all operations for provided user.
     * @param request Get operation list request.
     * @return Get operation list response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationListResponse operationList(OperationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Get pending operation list.
     * @param request Get pending operation list request.
     * @return Get pending operation list response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationListResponse operationPendingList(OperationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Cancel operation.
     * @param request Cancel operation request.
     * @return Cancel operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationDetailResponse operationCancel(OperationCancelRequest request) throws PowerAuthClientException;

    /**
     * Approve operation.
     * @param request Approve operation request.
     * @return Approve operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse operationApprove(OperationApproveRequest request) throws PowerAuthClientException;

    /**
     * Simulate approval failure. Useful when you need to enforce decrement of a counter,
     * or eventual operation failure.
     * @param request Failed approval operation request.
     * @return Failed approval operatin request.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws PowerAuthClientException;

    /**
     * Reject operation.
     * @param request Reject operation request.
     * @return Reject operation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationUserActionResponse operationReject(OperationRejectRequest request) throws PowerAuthClientException;

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
     * Create a new operation template.
     * @param request New operation template details.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) throws PowerAuthClientException;

    /**
     * Update an operation template.
     * @param request Updated operation template details.
     * @return Operation template detail.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) throws PowerAuthClientException;

    /**
     * Remove operation template.
     * @param request Remove operation template request.
     * @return Plain response object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    Response removeOperationTemplate(OperationTemplateDeleteRequest request) throws PowerAuthClientException;

    /**
     * Get the PowerAuth version 2 client (legacy).
     * @return PowerAuth version 2 client.
     */
    PowerAuthClientV2 v2() throws PowerAuthClientException;

    interface PowerAuthClientV2 {

        /**
         * Call the prepareActivation method of the PowerAuth 2.0 Server interface.
         * @param request {@link com.wultra.security.powerauth.client.v2.PrepareActivationRequest} instance
         * @return {@link com.wultra.security.powerauth.client.v2.PrepareActivationResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(com.wultra.security.powerauth.client.v2.PrepareActivationRequest request) throws PowerAuthClientException;

        /**
         * Call the prepareActivation method of the PowerAuth 2.0 Server interface.
         * @param activationIdShort Short activation ID.
         * @param activationName Name of this activation.
         * @param activationNonce Activation nonce.
         * @param applicationKey Application key of a given application.
         * @param applicationSignature Signature proving a correct application is sending the data.
         * @param cDevicePublicKey Device public key encrypted with activation OTP.
         * @param extras Additional, application specific information.
         * @return {@link com.wultra.security.powerauth.client.v2.PrepareActivationResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) throws PowerAuthClientException;

        /**
         * Create a new activation directly, using the createActivation method of the PowerAuth 2.0 Server interface.
         * @param request Create activation request.
         * @return Create activation response.
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(com.wultra.security.powerauth.client.v2.CreateActivationRequest request) throws PowerAuthClientException;

        /**
         * Call the createActivation method of the PowerAuth 2.0 Server interface.
         * @param userId User ID.
         * @param applicationKey Application key of a given application.
         * @param identity Identity fingerprint used during activation.
         * @param activationName Name of this activation.
         * @param activationNonce Activation nonce.
         * @param applicationSignature Signature proving a correct application is sending the data.
         * @param cDevicePublicKey Device public key encrypted with activation OTP.
         * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
         * @param extras Additional, application specific information.
         * @return {@link com.wultra.security.powerauth.client.v2.CreateActivationResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws PowerAuthClientException;

        /**
         * Call the createActivation method of the PowerAuth 2.0 Server interface.
         * @param userId User ID.
         * @param maxFailureCount Maximum failure count.
         * @param timestampActivationExpire Timestamp this activation should expire.
         * @param applicationKey Application key of a given application.
         * @param identity Identity fingerprint used during activation.
         * @param activationOtp Activation OTP.
         * @param activationName Name of this activation.
         * @param activationNonce Activation nonce.
         * @param applicationSignature Signature proving a correct application is sending the data.
         * @param cDevicePublicKey Device public key encrypted with activation OTP.
         * @param ephemeralPublicKey Ephemeral public key.
         * @param extras Additional, application specific information.
         * @return {@link com.wultra.security.powerauth.client.v2.CreateActivationResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws PowerAuthClientException;

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server interface.
         * @param request {@link com.wultra.security.powerauth.client.v2.VaultUnlockRequest} instance
         * @return {@link com.wultra.security.powerauth.client.v2.VaultUnlockResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(com.wultra.security.powerauth.client.v2.VaultUnlockRequest request) throws PowerAuthClientException;

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server interface.
         * @param activationId Activation Id of an activation to be used for authentication.
         * @param applicationKey Application Key of an application related to the activation.
         * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
         * @param signature Vault opening request signature.
         * @param signatureType Vault opening request signature type.
         * @param reason Reason why vault is being unlocked.
         * @return {@link com.wultra.security.powerauth.client.v2.VaultUnlockResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, com.wultra.security.powerauth.client.v2.SignatureType signatureType, String reason) throws PowerAuthClientException;

        /**
         * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface.
         * @param request {@link GetPersonalizedEncryptionKeyRequest} instance.
         * @return {@link GetPersonalizedEncryptionKeyResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws PowerAuthClientException;

        /**
         * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface and get
         * newly generated derived encryption key.
         * @param activationId Activation ID used for the key generation.
         * @return {@link GetPersonalizedEncryptionKeyResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) throws PowerAuthClientException;

        /**
         * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface.
         * @param request {@link GetNonPersonalizedEncryptionKeyRequest} instance.
         * @return {@link GetNonPersonalizedEncryptionKeyResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws PowerAuthClientException;

        /**
         * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface and get
         * newly generated derived encryption key.
         * @param applicationKey Application key of application used for the key generation.
         * @return {@link GetNonPersonalizedEncryptionKeyResponse}
         * @throws PowerAuthClientException In case REST API call fails.
         */
        GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) throws PowerAuthClientException;

        /**
         * Create a new token for basic token-based authentication.
         * @param request Request with token information.
         * @return Response with created token.
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(com.wultra.security.powerauth.client.v2.CreateTokenRequest request) throws PowerAuthClientException;

        /**
         * Create a new token for basic token-based authentication.
         * @param activationId Activation ID for the activation that is associated with the token.
         * @param ephemeralPublicKey Ephemeral public key used for response encryption.
         * @param signatureType Type of the signature used for validating the create request.
         * @return Response with created token.
         * @throws PowerAuthClientException In case REST API call fails.
         */
        com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, com.wultra.security.powerauth.client.v2.SignatureType signatureType) throws PowerAuthClientException;
    }

}
