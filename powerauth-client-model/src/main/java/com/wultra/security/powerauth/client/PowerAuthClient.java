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

import com.wultra.security.powerauth.client.model.entity.*;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.ActivationHistoryRequest;
import com.wultra.security.powerauth.client.model.request.AddActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.AddApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.BlockActivationRequest;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.request.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.ConfirmRecoveryCodeRequest;
import com.wultra.security.powerauth.client.model.request.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.CreateIntegrationRequest;
import com.wultra.security.powerauth.client.model.request.CreateNonPersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.CreatePersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.CreateRecoveryCodeRequest;
import com.wultra.security.powerauth.client.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.request.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationListRequest;
import com.wultra.security.powerauth.client.model.request.GetCallbackUrlListRequest;
import com.wultra.security.powerauth.client.model.request.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.request.GetErrorCodeListRequest;
import com.wultra.security.powerauth.client.model.request.GetIntegrationListRequest;
import com.wultra.security.powerauth.client.model.request.GetRecoveryConfigRequest;
import com.wultra.security.powerauth.client.model.request.GetSystemStatusRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.ListActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.ListApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.request.LookupRecoveryCodesRequest;
import com.wultra.security.powerauth.client.model.request.PrepareActivationRequest;
import com.wultra.security.powerauth.client.model.request.RecoveryCodeActivationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.RemoveCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.RemoveIntegrationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.request.RevokeRecoveryCodesRequest;
import com.wultra.security.powerauth.client.model.request.SignatureAuditRequest;
import com.wultra.security.powerauth.client.model.request.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.SupportApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.UnblockActivationRequest;
import com.wultra.security.powerauth.client.model.request.UnsupportApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.UpdateActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.UpdateActivationOtpRequest;
import com.wultra.security.powerauth.client.model.request.UpdateApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.UpdateRecoveryConfigRequest;
import com.wultra.security.powerauth.client.model.request.UpdateStatusForActivationsRequest;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.request.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.request.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.request.VerifyOfflineSignatureRequest;
import com.wultra.security.powerauth.client.model.request.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.CommitActivationResponse;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;

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
     * @return {@link com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @return {@link com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetSystemStatusRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException;

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param language ISO code for language.
     * @return {@link com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetErrorCodeListResponse getErrorList(String language) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link InitActivationRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(InitActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link com.wultra.security.powerauth.client.model.response.InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId        User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param otpValidation Mode that determines in which stage of activation should be additional OTP validated.
     * @param otp           Additional OTP value.
     * @return {@link com.wultra.security.powerauth.client.model.response.InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId, com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId                    User ID for which a new CREATED activation should be created.
     * @param applicationId             Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount           How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link com.wultra.security.powerauth.client.model.response.InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException;

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param userId                    User ID for which a new CREATED activation should be created.
     * @param applicationId             Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount           How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @param otpValidation             Mode that determines in which stage of activation should be additional OTP validated.
     * @param otp                       Additional OTP value.
     * @return {@link com.wultra.security.powerauth.client.model.response.InitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                                                                              com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException;

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link PrepareActivationRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.PrepareActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationCode     Activation code.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @param encryptedData      Encrypted data for ECIES.
     * @param mac                Mac of key and data for ECIES.
     * @param nonce              Nonce for ECIES.
     * @return {@link com.wultra.security.powerauth.client.model.response.PrepareActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth Server
     * interface.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateActivationResponse createActivation(CreateActivationRequest request) throws PowerAuthClientException;

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
     * @return {@link com.wultra.security.powerauth.client.model.response.CreateActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                                                                                  String applicationKey, String ephemeralPublicKey, String encryptedData,
                                                                                                  String mac, String nonce) throws PowerAuthClientException;

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param activationId   Activation ID for activation to be updated.
     * @param externalUserId User ID of user who updated the activation. Use null value if activation owner caused the change,
     *                       or if OTP value is automatically generated.
     * @param activationOtp  Value of activation OTP
     * @return {@link com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException;

    /**
     * Call the updateActivationOtp method of PowerAuth 3.1 Server interface.
     *
     * @param request {@link UpdateActivationOtpRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CommitActivationRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CommitActivationResponse commitActivation(CommitActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @return {@link com.wultra.security.powerauth.client.model.response.CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    CommitActivationResponse commitActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID for activation to be committed.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @param activationOtp  Value of activation OTP. Specify the value only when activation OTP should be validated during activation commit.
     * @return {@link com.wultra.security.powerauth.client.model.response.CommitActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetActivationStatusRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface. This method should be used only
     * to acquire the activation status for other, than PowerAuth standard RESTful API purposes. If you're implementing
     * the PowerAuth standard RESTful API, then use {@link #getActivationStatusWithEncryptedStatusBlob(String, String)}
     * method instead.
     *
     * @param activationId Activation Id to lookup information for.
     * @return {@link com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException;

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server interface. The method should be used to
     * acquire the activation status for PowerAuth standard RESTful API implementation purposes. The returned object
     * contains an encrypted activation status blob.
     *
     * @param activationId Activation Id to lookup information for.
     * @param challenge    Cryptographic challenge for activation status blob encryption.
     * @return {@link com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link RemoveActivationRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be removed.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @return {@link com.wultra.security.powerauth.client.model.response.RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId        Activation ID of activation to be removed.
     * @param externalUserId      User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @param revokeRecoveryCodes Indicates if the recovery codes associated with this activation should be also revoked.
     * @return {@link com.wultra.security.powerauth.client.model.response.RemoveActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveActivationResponse removeActivation(String activationId, String externalUserId, Boolean revokeRecoveryCodes) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link GetActivationListForUserRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.GetActivationListForUserResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server interface.
     *
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<Activation> getActivationListForUser(String userId) throws PowerAuthClientException;

    /**
     * Call the lookupActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link LookupActivationsRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.LookupActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws PowerAuthClientException;

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
    List<Activation> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link UpdateStatusForActivationsRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.UpdateStatusForActivationsResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws PowerAuthClientException;

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server interface.
     *
     * @param activationIds    Identifiers of activations whose status should be updated.
     * @param activationStatus Activation status to be used.
     * @return Response indicating whether activation status update succeeded.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifySignatureRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.VerifySignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CreatePersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException;

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID.
     * @param data         Data for offline signature.
     * @return {@link com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link CreateNonPersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException;

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server interface.
     *
     * @param applicationId Application ID.
     * @param data          Data for offline signature.
     * @return {@link com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) throws PowerAuthClientException;

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifyOfflineSignatureRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) throws PowerAuthClientException;

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VaultUnlockRequest} instance
     * @return {@link com.wultra.security.powerauth.client.model.response.VaultUnlockResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException;

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
     * @return {@link com.wultra.security.powerauth.client.model.response.VaultUnlockResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                                                                        SignatureType signatureType, String signatureVersion, String signedData,
                                                                                        String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link VerifyECDSASignatureRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws PowerAuthClientException;

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data         Data that were signed by ECDSA algorithm.
     * @param signature    Request signature.
     * @return Verify ECDSA signature and return REST response with the verification results.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws PowerAuthClientException;

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link SignatureAuditRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.SignatureAuditResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface and get
     * signature audit log for all application of a given user.
     *
     * @param userId       User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of signature audit items.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<SignatureAuditItem> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server interface and get
     * signature audit log for a single application.
     *
     * @param userId        User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate  Limit the results to given starting date (= "newer than").
     * @param endingDate    Limit the results to given ending date (= "older than").
     * @return List of signature audit items.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<SignatureAuditItem> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link ActivationHistoryRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws PowerAuthClientException;

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId Activation ID.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate   Limit the results to given ending date (= "older than").
     * @return List of activation history items.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<ActivationHistoryItem> getActivationHistory(String activationId, Date startingDate, Date endingDate) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link BlockActivationRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.BlockActivationResponse blockActivation(BlockActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be blocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @param reason         Reason why activation is being blocked.
     * @return {@link com.wultra.security.powerauth.client.model.response.BlockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param request {@link UnblockActivationRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.UnblockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws PowerAuthClientException;

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server interface.
     *
     * @param activationId   Activation ID of activation to be unblocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @return {@link com.wultra.security.powerauth.client.model.response.UnblockActivationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UnblockActivationResponse unblockActivation(String activationId, String externalUserId) throws PowerAuthClientException;

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @param request {@link GetApplicationListRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.GetApplicationListResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws PowerAuthClientException;

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     *
     * @return List of applications.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<Application> getApplicationList() throws PowerAuthClientException;

    /**
     * Return the detail of given application, including all application versions.
     *
     * @param request {@link GetApplicationDetailRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException;

    /**
     * Get the detail of an application with given ID, including the version list.
     *
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws PowerAuthClientException;

    /**
     * Get the detail of an application with given name, including the version list.
     *
     * @param applicationName name of an application to fetch.
     * @return Application with given name, including the version list.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse getApplicationDetail(String applicationName) throws PowerAuthClientException;

    /**
     * Lookup an application by application key.
     *
     * @param request {@link LookupApplicationByAppKeyRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws PowerAuthClientException;

    /**
     * Lookup an application by application key.
     *
     * @param applicationKey Application key.
     * @return Response with application ID.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) throws PowerAuthClientException;

    /**
     * Create a new application with given name.
     *
     * @param request {@link CreateApplicationRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.CreateApplicationResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateApplicationResponse createApplication(CreateApplicationRequest request) throws PowerAuthClientException;

    /**
     * Create a new application with given name.
     *
     * @param name Name of the new application.
     * @return Application with a given name.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateApplicationResponse createApplication(String name) throws PowerAuthClientException;

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param request {@link CreateApplicationVersionRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws PowerAuthClientException;

    /**
     * Create a version with a given name for an application with given ID.
     *
     * @param applicationId ID of an application to create a version for.
     * @param versionName   Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws PowerAuthClientException;

    /**
     * Cancel the support for a given application version.
     *
     * @param request {@link UnsupportApplicationVersionRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws PowerAuthClientException;

    /**
     * Cancel the support for a given application version.
     *
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws PowerAuthClientException;

    /**
     * Renew the support for a given application version.
     *
     * @param request {@link SupportApplicationVersionRequest} instance.
     * @return {@link com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse}
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws PowerAuthClientException;

    /**
     * Renew the support for a given application version.
     *
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws PowerAuthClientException;

    /**
     * Create a new integration with given name.
     *
     * @param request Request specifying the integration name.
     * @return New integration information.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws PowerAuthClientException;

    /**
     * Create a new integration with given name.
     *
     * @param name Integration name.
     * @return New integration information.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse createIntegration(String name) throws PowerAuthClientException;

    /**
     * Get the list of integrations.
     *
     * @param request REST request object.
     * @return List of integrations.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws PowerAuthClientException;

    /**
     * Get the list of integrations.
     *
     * @return List of integrations.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<Integration> getIntegrationList() throws PowerAuthClientException;

    /**
     * Remove integration with given ID.
     *
     * @param request REST object with integration ID to be removed.
     * @return Removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws PowerAuthClientException;

    /**
     * Remove integration with given ID.
     *
     * @param id ID of integration to be removed.
     * @return Removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse removeIntegration(String id) throws PowerAuthClientException;

    /**
     * Create a new callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Create a new callback URL with given parameters.
     *
     * @param applicationId Application ID.
     * @param name          Callback URL display name.
     * @param callbackUrl   Callback URL value.
     * @param attributes    Attributes to send in the callback data.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl, List<String> attributes) throws PowerAuthClientException;

    /**
     * Update a callback URL with given request object.
     *
     * @param request REST request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Update a callback URL with given parameters.
     *
     * @param id            Callback URL identifier.
     * @param applicationId Application ID.
     * @param name          Callback URL display name.
     * @param callbackUrl   Callback URL value.
     * @param attributes    Attributes to send in the callback data.
     * @return Information about new callback URL object.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse updateCallbackUrl(String id, long applicationId, String name, String callbackUrl, List<String> attributes) throws PowerAuthClientException;

    /**
     * Get the response with list of callback URL objects.
     *
     * @param request REST request object with application ID.
     * @return Response with the list of all callback URLs for given application.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws PowerAuthClientException;

    /**
     * Get the list of callback URL objects.
     *
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    List<CallbackUrl> getCallbackUrlList(Long applicationId) throws PowerAuthClientException;

    /**
     * Remove callback URL.
     *
     * @param request Remove callback URL request.
     * @return Information about removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws PowerAuthClientException;

    /**
     * Remove callback URL.
     *
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws PowerAuthClientException;

    /**
     * Create a new token for basic token-based authentication.
     *
     * @param request Request with token information.
     * @return Response with created token.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateTokenResponse createToken(CreateTokenRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                                        String encryptedData, String mac, String nonce, SignatureType signatureType) throws PowerAuthClientException;

    /**
     * Validate credentials used for basic token-based authentication.
     *
     * @param request Credentials to validate.
     * @return Response with the credentials validation status.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ValidateTokenResponse validateToken(ValidateTokenRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws PowerAuthClientException;

    /**
     * Remove token with given token ID.
     *
     * @param request Request with token ID.
     * @return Response token removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveTokenResponse removeToken(RemoveTokenRequest request) throws PowerAuthClientException;

    /**
     * Remove token with given token ID.
     *
     * @param tokenId      Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException;

    /**
     * Get ECIES decryptor parameters.
     *
     * @param request Request for ECIES decryptor parameters.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws PowerAuthClientException;

    /**
     * Get ECIES decryptor parameters.
     *
     * @param activationId       Activation ID.
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral key for ECIES.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthClientException;

    /**
     * Start upgrade of activations to version 3.
     *
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                                          String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws PowerAuthClientException;

    /**
     * Commit upgrade of activations to version 3.
     *
     * @param activationId   Activation ID.
     * @param applicationKey Application key.
     * @return Commit upgrade response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) throws PowerAuthClientException;

    /**
     * Create recovery code.
     *
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws PowerAuthClientException;

    /**
     * Create recovery code for user.
     *
     * @param applicationId Application ID.
     * @param userId        User ID.
     * @param pukCount      Number of PUKs to create.
     * @return Create recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount) throws PowerAuthClientException;

    /**
     * Confirm recovery code.
     *
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                                                        String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Lookup recovery codes.
     *
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                                                                        com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus recoveryCodeStatus, com.wultra.security.powerauth.client.model.enumeration.RecoveryPukStatus recoveryPukStatus) throws PowerAuthClientException;

    /**
     * Revoke recovery codes.
     *
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws PowerAuthClientException;

    /**
     * Revoke recovery codes.
     *
     * @param recoveryCodeIds Identifiers of recovery codes to revoke.
     * @return Revoke recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) throws PowerAuthClientException;

    /**
     * Create activation using recovery code.
     *
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                                                                         String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException;

    /**
     * Get recovery configuration.
     *
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws PowerAuthClientException;

    /**
     * Get recovery configuration.
     *
     * @param applicationId Application ID.
     * @return Get recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.GetRecoveryConfigResponse getRecoveryConfig(Long applicationId) throws PowerAuthClientException;

    /**
     * Update recovery configuration.
     *
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws PowerAuthClientException;

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
    com.wultra.security.powerauth.client.model.response.UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) throws PowerAuthClientException;

    /**
     * List activation flags.
     *
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * List activation flags.
     *
     * @param activationId Activation ID.
     * @return List activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse listActivationFlags(String activationId) throws PowerAuthClientException;

    /**
     * Add activation flags.
     *
     * @param request Add activation flags request.
     * @return Add activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * Add activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Add activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse addActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Update activation flags.
     *
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * Update activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Update activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * Remove activation flags.
     *
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws PowerAuthClientException;

    /**
     * Remove activation flags.
     *
     * @param activationId    Activation ID.
     * @param activationFlags Activation flags.
     * @return Remove activation flags response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException;

    /**
     * List application roles.
     * @param request List application roles request.
     * @return List application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * List application roles.
     * @param applicationId Application ID.
     * @return List application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse listApplicationRoles(Long applicationId) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param request Add application roles request.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Add application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to add.
     * @return Add application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse addApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Update application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to set.
     * @return Update application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse updateApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws PowerAuthClientException;

    /**
     * Remove application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles to remove.
     * @return Remove application roles response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse removeApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException;

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

}
