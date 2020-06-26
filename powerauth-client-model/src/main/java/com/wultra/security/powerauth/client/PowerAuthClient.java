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

import com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest;
import com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse;
import com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest;
import com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse;
import com.wultra.security.powerauth.client.v3.*;

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
     */
    GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request);

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @return {@link GetSystemStatusResponse}
     */
    GetSystemStatusResponse getSystemStatus();

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetSystemStatusRequest} instance
     * @return {@link GetSystemStatusResponse}
     */
    GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request);

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param language ISO code for language.
     * @return {@link GetSystemStatusResponse}
     */
    GetErrorCodeListResponse getErrorList(String language);

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link InitActivationRequest} instance
     * @return {@link InitActivationResponse}
     */
    InitActivationResponse initActivation(InitActivationRequest request);

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link InitActivationResponse}
     */
    InitActivationResponse initActivation(String userId, Long applicationId);

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param otpValidation Mode that determines in which stage of activation should be additional OTP validated.
     * @param otp           Additional OTP value.
     * @return {@link InitActivationResponse}
     */
    InitActivationResponse initActivation(String userId, Long applicationId, ActivationOtpValidation otpValidation, String otp);

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId                    User ID for which a new CREATED activation should be created.
     * @param applicationId             Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount           How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link InitActivationResponse}
     */
    InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire);

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
     */
    InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                          ActivationOtpValidation otpValidation, String otp);

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link PrepareActivationRequest} instance
     * @return {@link PrepareActivationResponse}
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request);

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
     */
    PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce);

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth Server
     * interface.
     *
     * @param request Create activation request.
     * @return Create activation response.
     */
    CreateActivationResponse createActivation(CreateActivationRequest request);

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
     */
    CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                              String applicationKey, String ephemeralPublicKey, String encryptedData,
                                              String mac, String nonce);

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param activationId   Activation ID for activation to be updated.
     * @param externalUserId User ID of user who updated the activation. Use null value if activation owner caused the change,
     *                       or if OTP value is automatically generated.
     * @param activationOtp  Value of activation OTP
     * @return {@link UpdateActivationOtpResponse}
     */
    UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp);

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param request {@link UpdateActivationOtpRequest} instance
     * @return {@link UpdateActivationOtpResponse}
     */
    UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request);

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CommitActivationRequest} instance
     * @return {@link CommitActivationResponse}
     */
    CommitActivationResponse commitActivation(CommitActivationRequest request);

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @return {@link CommitActivationResponse}
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId);

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @param activationOtp  Value of activation OTP. Specify the value only when activation OTP should be validated during activation commit.
     * @return {@link CommitActivationResponse}
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp);

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetActivationStatusRequest} instance
     * @return {@link GetActivationStatusResponse}
     */
    GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request);

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface. This method should be used only
     * to acquire the activation status for other, than PowerAuth standard RESTful API purposes. If you're implementing
     * the PowerAuth standard RESTful API, then use {@link #getActivationStatusWithEncryptedStatusBlob(String, String)}
     * method instead.
     *
     * @param activationId Activation Id to lookup information for.
     * @return {@link GetActivationStatusResponse}
     */
    GetActivationStatusResponse getActivationStatus(String activationId);

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface. The method should be used to
     * acquire the activation status for PowerAuth standard RESTful API implementation purposes. The returned object
     * contains an encrypted activation status blob.
     *
     * @param activationId Activation Id to lookup information for.
     * @param challenge    Cryptographic challenge for activation status blob encryption.
     * @return {@link GetActivationStatusResponse}
     */
    GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge);

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link RemoveActivationRequest} instance.
     * @return {@link RemoveActivationResponse}
     */
    RemoveActivationResponse removeActivation(RemoveActivationRequest request);

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be removed.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @return {@link RemoveActivationResponse}
     */
    RemoveActivationResponse removeActivation(String activationId, String externalUserId);

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId        Activation ID of activation to be removed.
     * @param externalUserId      User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @param revokeRecoveryCodes Indicates if the recovery codes associated with this activation should be also revoked.
     * @return {@link RemoveActivationResponse}
     */
    RemoveActivationResponse removeActivation(String activationId, String externalUserId, Boolean revokeRecoveryCodes);

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetActivationListForUserRequest} instance
     * @return {@link GetActivationListForUserResponse}
     */
    GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request);

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server interface.
     *
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     */
    List<GetActivationListForUserResponse.Activations> getActivationListForUser(String userId);

    /**
     * Call the lookupActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link LookupActivationsRequest} instance
     * @return {@link LookupActivationsResponse}
     */
    LookupActivationsResponse lookupActivations(LookupActivationsRequest request);

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
     */
    List<LookupActivationsResponse.Activations> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags);

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link UpdateStatusForActivationsRequest} instance
     * @return {@link UpdateStatusForActivationsResponse}
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request);

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param activationIds    Identifiers of activations whose status should be updated.
     * @param activationStatus Activation status to be used.
     * @return Response indicating whether activation status update succeeded.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus);

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifySignatureRequest} instance.
     * @return {@link VerifySignatureResponse}
     */
    VerifySignatureResponse verifySignature(VerifySignatureRequest request);

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
     */
    VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion);

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CreatePersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link CreatePersonalizedOfflineSignaturePayloadResponse}
     */
    CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request);

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID.
     * @param data         Data for offline signature.
     * @return {@link CreatePersonalizedOfflineSignaturePayloadResponse}
     */
    CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data);

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CreateNonPersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link CreateNonPersonalizedOfflineSignaturePayloadResponse}
     */
    CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request);

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param applicationId Application ID.
     * @param data          Data for offline signature.
     * @return {@link CreateNonPersonalizedOfflineSignaturePayloadResponse}
     */
    CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data);

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifyOfflineSignatureRequest} instance.
     * @return {@link VerifyOfflineSignatureResponse}
     */
    VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request);

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId  Activation ID.
     * @param data          Data for signature.
     * @param signature     Signature value.
     * @param allowBiometry Whether POSSESSION_BIOMETRY signature type is allowed during signature verification.
     * @return Offline signature verification response.
     */
    VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry);

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VaultUnlockRequest} instance
     * @return {@link VaultUnlockResponse}
     */
    VaultUnlockResponse unlockVault(VaultUnlockRequest request);

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
     */
    VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                    SignatureType signatureType, String signatureVersion, String signedData,
                                    String ephemeralPublicKey, String encryptedData, String mac, String nonce);

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifyECDSASignatureRequest} instance.
     * @return {@link VerifyECDSASignatureResponse}
     */
    VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request);

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data         Data that were signed by ECDSA algorithm.
     * @param signature    Request signature.
     * @return Verify ECDSA signature and return REST response with the verification results.
     */
    VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature);

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link SignatureAuditRequest} instance.
     * @return {@link SignatureAuditResponse}
     */
    SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request);

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface and get
     * signature audit log for all application of a given user.
     *
     * @param userId       User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link com.wultra.security.powerauth.client.v3.SignatureAuditResponse.Items}.
     */
    List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate);

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface and get
     * signature audit log for a single application.
     *
     * @param userId        User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate  Limit the results to given starting date (= "newer than").
     * @param endingDate    Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link com.wultra.security.powerauth.client.v3.SignatureAuditResponse.Items}.
     */
    List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate);

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link ActivationHistoryRequest} instance.
     * @return {@link ActivationHistoryResponse}
     */
    ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request);

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of activation history items. See: {@link com.wultra.security.powerauth.client.v3.ActivationHistoryResponse.Items}.
     */
    List<ActivationHistoryResponse.Items> getActivationHistory(String activationId, Date startingDate, Date endingDate);

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link BlockActivationRequest} instance.
     * @return {@link BlockActivationResponse}
     */
    BlockActivationResponse blockActivation(BlockActivationRequest request);

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be blocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @param reason         Reason why activation is being blocked.
     * @return {@link BlockActivationResponse}
     */
    BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId);

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link UnblockActivationRequest} instance.
     * @return {@link UnblockActivationResponse}
     */
    UnblockActivationResponse unblockActivation(UnblockActivationRequest request);

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be unblocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @return {@link UnblockActivationResponse}
     */
    UnblockActivationResponse unblockActivation(String activationId, String externalUserId);

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @param request {@link GetApplicationListRequest} instance.
     * @return {@link GetApplicationListResponse}
     */
    GetApplicationListResponse getApplicationList(GetApplicationListRequest request);

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @return List of applications.
     */
    List<GetApplicationListResponse.Applications> getApplicationList();

    /**
     * Return the detail of given application, including all application versions.
     *
     * @param request {@link GetApplicationDetailRequest} instance.
     * @return {@link GetApplicationDetailResponse}
     */
    GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request);

    /**
     * Get the detail of an application with given ID, including the version list.
     *
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     */
    GetApplicationDetailResponse getApplicationDetail(Long applicationId);

    /**
     * Get the detail of an application with given name, including the version list.
     *
     * @param applicationName name of an application to fetch.
     * @return Application with given name, including the version list.
     */
    GetApplicationDetailResponse getApplicationDetail(String applicationName);

    /**
     * Lookup an application by application key.
     *
     * @param request {@link LookupApplicationByAppKeyRequest} instance.
     * @return {@link LookupApplicationByAppKeyResponse}
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request);

    /**
     * Lookup an application by application key.
     *
     * @param applicationKey Application key.
     * @return Response with application ID.
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey);

    /**
     * Create a new application with given name.
     *
     * @param request {@link CreateApplicationRequest} instance.
     * @return {@link CreateApplicationResponse}
     */
    CreateApplicationResponse createApplication(CreateApplicationRequest request);

    /**
     * Create a new application with given name.
     *
     * @param name Name of the new application.
     * @return Application with a given name.
     */
    CreateApplicationResponse createApplication(String name);

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param request {@link CreateApplicationVersionRequest} instance.
     * @return {@link CreateApplicationVersionResponse}
     */
    CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request);

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param applicationId ID of an application to create a version for.
     * @param versionName   Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     */
    CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName);

    /**
     * Cancel the support for a given application version.
     *
     * @param request {@link UnsupportApplicationVersionRequest} instance.
     * @return {@link UnsupportApplicationVersionResponse}
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request);

    /**
     * Cancel the support for a given application version.
     *
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId);

    /**
     * Renew the support for a given application version.
     *
     * @param request {@link SupportApplicationVersionRequest} instance.
     * @return {@link SupportApplicationVersionResponse}
     */
    SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request);

    /**
     * Renew the support for a given application version.
     *
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     */
    SupportApplicationVersionResponse supportApplicationVersion(Long versionId);

    /**
     * Create a new integration with given name.
     *
     * @param request Request specifying the integration name.
     * @return New integration information.
     */
    CreateIntegrationResponse createIntegration(CreateIntegrationRequest request);

    /**
     * Create a new integration with given name.
     *
     * @param name Integration name.
     * @return New integration information.
     */
    CreateIntegrationResponse createIntegration(String name);

    /**
     * Get the list of integrations.
     *
     * @param request REST request object.
     * @return List of integrations.
     */
    GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request);

    /**
     * Get the list of integrations.
     *
     * @return List of integrations.
     */
    List<GetIntegrationListResponse.Items> getIntegrationList();

    /**
     * Remove integration with given ID.
     *
     * @param request REST object with integration ID to be removed.
     * @return Removal status.
     */
    RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request);

    /**
     * Remove integration with given ID.
     *
     * @param id ID of integration to be removed.
     * @return Removal status.
     */
    RemoveIntegrationResponse removeIntegration(String id);

    /**
     * Create a new callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @return Information about new callback URL object.
     */
    CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request);

    /**
     * Create a new callback URL with given parameters.
     *
     * @param applicationId Application ID.
     * @param name          Callback URL display name.
     * @param callbackUrl   Callback URL value.
     * @return Information about new callback URL object.
     */
    CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl);

    /**
     * Get the response with list of callback URL objects.
     *
     * @param request REST request object with application ID.
     * @return Response with the list of all callback URLs for given application.
     */
    GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request);

    /**
     * Get the list of callback URL objects.
     *
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     */
    List<GetCallbackUrlListResponse.CallbackUrlList> getCallbackUrlList(Long applicationId);

    /**
     * Remove callback URL.
     *
     * @param request Remove callback URL request.
     * @return Information about removal status.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request);

    /**
     * Remove callback URL.
     *
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId);

    /**
     * Create a new token for basic token-based authentication.
     *
     * @param request Request with token information.
     * @return Response with created token.
     */
    CreateTokenResponse createToken(CreateTokenRequest request);

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
     */
    CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                    String encryptedData, String mac, String nonce, SignatureType signatureType);

    /**
     * Validate credentials used for basic token-based authentication.
     *
     * @param request Credentials to validate.
     * @return Response with the credentials validation status.
     */
    ValidateTokenResponse validateToken(ValidateTokenRequest request);

    /**
     * Validate credentials used for basic token-based authentication.
     *
     * @param tokenId     Token ID.
     * @param nonce       Random token nonce.
     * @param timestamp   Token timestamp.
     * @param tokenDigest Token digest.
     * @return Response with the credentials validation status.
     */
    ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest);

    /**
     * Remove token with given token ID.
     *
     * @param request Request with token ID.
     * @return Response token removal result.
     */
    RemoveTokenResponse removeToken(RemoveTokenRequest request);

    /**
     * Remove token with given token ID.
     *
     * @param tokenId      Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     */
    RemoveTokenResponse removeToken(String tokenId, String activationId);

    /**
     * Get ECIES decryptor parameters.
     *
     * @param request Request for ECIES decryptor parameters.
     * @return ECIES decryptor parameters.
     */
    GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request);

    /**
     * Get ECIES decryptor parameters.
     *
     * @param activationId       Activation ID.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @return ECIES decryptor parameters.
     */
    GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey);

    /**
     * Start upgrade of activations to version 3.
     *
     * @param request Start upgrade request.
     * @return Start upgrade response.
     */
    StartUpgradeResponse startUpgrade(StartUpgradeRequest request);

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
     */
    StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                      String encryptedData, String mac, String nonce);

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     */
    CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request);

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param activationId   Activation ID.
     * @param applicationKey Application key.
     * @return Commit upgrade response.
     */
    CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey);

    /**
     * Create recovery code.
     *
     * @param request Create recovery code request.
     * @return Create recovery code response.
     */
    CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request);

    /**
     * Create recovery code for user.
     *
     * @param applicationId Application ID.
     * @param userId        User ID.
     * @param pukCount      Number of PUKs to create.
     * @return Create recovery code response.
     */
    CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount);

    /**
     * Confirm recovery code.
     *
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     */
    ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request);

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
     */
    ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                    String encryptedData, String mac, String nonce);

    /**
     * Lookup recovery codes.
     *
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     */
    LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request);

    /**
     * Lookup recovery codes.
     *
     * @param userId             User ID.
     * @param activationId       Activation ID.
     * @param applicationId      Application ID.
     * @param recoveryCodeStatus Recovery code status.
     * @param recoveryPukStatus  Recovery PUK status.
     * @return Lookup recovery codes response.
     */
    LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                    RecoveryCodeStatus recoveryCodeStatus, RecoveryPukStatus recoveryPukStatus);

    /**
     * Revoke recovery codes.
     *
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     */
    RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request);

    /**
     * Revoke recovery codes.
     *
     * @param recoveryCodeIds Identifiers of recovery codes to revoke.
     * @return Revoke recovery code response.
     */
    RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds);

    /**
     * Create activation using recovery code.
     *
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     */
    RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request);

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
     */
    RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                     String ephemeralPublicKey, String encryptedData, String mac, String nonce);

    /**
     * Get recovery configuration.
     *
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     */
    GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request);

    /**
     * Get recovery configuration.
     *
     * @param applicationId Application ID.
     * @return Get recovery configuration response.
     */
    GetRecoveryConfigResponse getRecoveryConfig(Long applicationId);

    /**
     * Update recovery configuration.
     *
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     */
    UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request);

    /**
     * Update recovery configuration.
     *
     * @param applicationId                 Application ID.
     * @param activationRecoveryEnabled     Whether activation recovery is enabled.
     * @param recoveryPostcardEnabled       Whether recovery postcard is enabled.
     * @param allowMultipleRecoveryCodes    Whether multiple recovery codes are allowed.
     * @param remoteRecoveryPublicKeyBase64 Base64 encoded remote key.
     * @return Update recovery configuration response.
     */
    UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64);

    /**
     * List activation flags.
     *
     * @param request List activation flags request.
     * @return List activation flags response.
     */
    ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request);

    /**
     * List activation flags.
     *
     * @param activationId Activation ID.
     * @return List activation flags response.
     */
    ListActivationFlagsResponse listActivationFlags(String activationId);

    /**
     * Create activation flags.
     *
     * @param request Create activation flags request.
     * @return Create activation flags response.
     */
    CreateActivationFlagsResponse createActivationFlags(CreateActivationFlagsRequest request);

    /**
     * Create activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Create activation flags response.
     */
    CreateActivationFlagsResponse createActivationFlags(String activationId, List<String> activationFlags);

    /**
     * Update activation flags.
     *
     * @param request Update activation flags request.
     * @return Update activation flags response.
     */
    UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request);

    /**
     * Update activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Update activation flags response.
     */
    UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags);

    /**
     * Remove activation flags.
     *
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     */
    RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request);

    /**
     * Remove activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Remove activation flags response.
     */
    RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags);

    /**
     * Get the PowerAuth version 2 client (legacy).
     * @return PowerAuth version 2 client.
     */
    PowerAuthClientV2 v2();

    public interface PowerAuthClientV2 {

        /**
         * Call the prepareActivation method of the PowerAuth 2.0 Server interface.
         * @param request {@link com.wultra.security.powerauth.client.v2.PrepareActivationRequest} instance
         * @return {@link com.wultra.security.powerauth.client.v2.PrepareActivationResponse}
         */
        com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(com.wultra.security.powerauth.client.v2.PrepareActivationRequest request);

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
         */
        com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature);

        /**
         * Create a new activation directly, using the createActivation method of the PowerAuth 2.0 Server interface.
         * @param request Create activation request.
         * @return Create activation response.
         */
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(com.wultra.security.powerauth.client.v2.CreateActivationRequest request);

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
         */
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature);

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
         */
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature);

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server interface.
         * @param request {@link com.wultra.security.powerauth.client.v2.VaultUnlockRequest} instance
         * @return {@link com.wultra.security.powerauth.client.v2.VaultUnlockResponse}
         */
        com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(com.wultra.security.powerauth.client.v2.VaultUnlockRequest request);

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server interface.
         * @param activationId Activation Id of an activation to be used for authentication.
         * @param applicationKey Application Key of an application related to the activation.
         * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
         * @param signature Vault opening request signature.
         * @param signatureType Vault opening request signature type.
         * @param reason Reason why vault is being unlocked.
         * @return {@link com.wultra.security.powerauth.client.v2.VaultUnlockResponse}
         */
        com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, com.wultra.security.powerauth.client.v2.SignatureType signatureType, String reason);

        /**
         * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface.
         * @param request {@link GetPersonalizedEncryptionKeyRequest} instance.
         * @return {@link GetPersonalizedEncryptionKeyResponse}
         */
        GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(GetPersonalizedEncryptionKeyRequest request);

        /**
         * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface and get
         * newly generated derived encryption key.
         * @param activationId Activation ID used for the key generation.
         * @return {@link GetPersonalizedEncryptionKeyResponse}
         */
        GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex);

        /**
         * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface.
         * @param request {@link GetNonPersonalizedEncryptionKeyRequest} instance.
         * @return {@link GetNonPersonalizedEncryptionKeyResponse}
         */
        GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request);

        /**
         * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server interface and get
         * newly generated derived encryption key.
         * @param applicationKey Application key of application used for the key generation.
         * @return {@link GetNonPersonalizedEncryptionKeyResponse}
         */
        GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex);

        /**
         * Create a new token for basic token-based authentication.
         * @param request Request with token information.
         * @return Response with created token.
         */
        com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(com.wultra.security.powerauth.client.v2.CreateTokenRequest request);

        /**
         * Create a new token for basic token-based authentication.
         * @param activationId Activation ID for the activation that is associated with the token.
         * @param ephemeralPublicKey Ephemeral public key used for response encryption.
         * @param signatureType Type of the signature used for validating the create request.
         * @return Response with created token.
         */
        com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, com.wultra.security.powerauth.client.v2.SignatureType signatureType);
    }

}
