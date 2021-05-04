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
package io.getlime.security.powerauth.app.server.service.v3;

import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.v3.*;

/**
 * Interface containing all methods that are published by the PowerAuth 3.0 Server
 * instance. These methods are then used to publish both SOAP and REST interface.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface PowerAuthService {

    /**
     * Get PowerAuth 3.0 Server system status.
     *
     * @param request Empty object.
     * @return System status.
     * @throws Exception In case of a business logic error.
     */
    GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws Exception;

    /**
     * Get activations for a given user.
     *
     * @param request Activation list request object.
     * @return Activation list.
     * @throws Exception In case of a business logic error.
     */
    GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws Exception;

    /**
     * Lookup activations using various query parameters.
     * @param request Lookup activations request.
     * @return Lookup activations response.
     * @throws Exception In case of a business logic error.
     */
    LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws Exception;

    /**
     * Update status for activations.
     * @param request Update status for activations request.
     * @return Update status for activations response.
     * @throws Exception In case of a business logic error.
     */
    UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws Exception;

    /**
     * Get activation status for given activation ID.
     *
     * @param request Activation status request object.
     * @return Activation status.
     * @throws Exception In case of a business logic error.
     */
    GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception;

    /**
     * Get the list of error codes for given language.
     *
     * @param request Error code list request object.
     * @return Error code list.
     * @throws Exception In case of a business logic error.
     */
    GetErrorCodeListResponse getErrorCodeList(GetErrorCodeListRequest request) throws Exception;

    /**
     * Initiate a new activation for a given application and user ID. The new activation record is in
     * CREATED state after calling this method.
     *
     * @param request Init activation request object.
     * @return Activation init data.
     * @throws Exception In case of a business logic error.
     */
    InitActivationResponse initActivation(InitActivationRequest request) throws Exception;

    /**
     * Receive a PowerAuth 3.0 Client public key and return own PowerAuth 3.0 Server public key. The
     * activation with provided ID is in PENDING_COMMIT or ACTIVE state after calling this method, depending on
     * presence of activation OTP in encrypted data.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>

     * @param request Prepare activation request object.
     * @return Prepare activation response.
     * @throws Exception In case of a business logic error.
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception;

    /**
     * Create a new activation in PENDING_COMMIT state, without the InitActivation / PrepareActivation cycle.
     * This method receives a PowerAuth 3.0 Client public key and returns own PowerAuth 3.0 Server public key.
     * The activation with is in PENDING_COMMIT state after calling this method.
     *
     * Note: This method should be used in case of activation performed directly, without the external
     * master front end application.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Create activation request object.
     * @return Create activation response.
     * @throws Exception In case of a business logic error.
     */
    CreateActivationResponse createActivation(CreateActivationRequest request) throws Exception;

    /**
     * Verify signature against provided data using activation with given ID. Each call to this method
     * increments a counter associated with an activation with given ID. In case too many failed
     * verification attempts occur (max. fail count is a property of an activation, default is 5),
     * activation is moved to BLOCKED state. In case a successful verification occurs, the fail counter
     * is reset back to zero.
     *
     * @param request Verify signature request object.
     * @return Signature verification response.
     * @throws Exception In case of a business logic error.
     */
    VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception;

    /**
     * Generate data that is used as a challenge when computing personalized offline signatures. It takes "data" and
     * generates nonce and ECDSA signature of the data.
     *
     * @param request Request with data and message to generate signature from.
     * @return Response with offline signature data.
     * @throws Exception In case of a business logic error.
     */
    CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws Exception;

    /**
     * Generate data that is used as a challenge when computing non-personalized offline signatures. It takes "data" and
     * generates nonce and ECDSA signature of the data.
     *
     * @param request Request with data and message to generate signature from.
     * @return Response with offline signature data.
     * @throws Exception In case of a business logic error.
     */
    CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws Exception;

    /**
     * Verify offline signature. Each call to this method
     * increments a counter associated with an activation with given ID. In case too many failed
     * verification attempts occur (max. fail count is a property of an activation, default is 5),
     * activation is moved to BLOCKED state. In case a successful verification occurs, the fail counter
     * is reset back to zero.
     *
     * @param request Request for verification of a provided signature.
     * @return Signature verification response.
     * @throws Exception In case of a business logic error.
     */
    VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws Exception;

    /**
     * Update activation OTP before activation commit.
     *
     * @param request Activation OTP update request object.
     * @return Activation OTP update response object.
     * @throws Exception In case of a business logic error.
     */
    UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws Exception;

    /**
     * Commit a created activation. Only activations in PENDING_COMMIT state can be committed - in case activation
     * is in other state, exception is raised. In case of successful call of this method, activation with
     * provided ID is in ACTIVE state.
     *
     * @param request Activation commit request object.
     * @return Activation commit response.
     * @throws Exception In case of a business logic error.
     */
    CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception;

    /**
     * Remove activation with given ID - change it's status to REMOVED. Activations in any state can be removed.
     *
     * @param request Activation remove request object.
     * @return Activation remove response.
     * @throws Exception In case of a business logic error.
     */
    RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception;

    /**
     * Block activation with given ID. Activation moves to BLOCKED state, only activations in ACTIVE state
     * can be blocked. Attempt to block an activation in incorrect state results in exception.
     *
     * @param request Block activation request object.
     * @return Block activation response.
     * @throws Exception In case of a business logic error.
     */
    BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception;

    /**
     * Unblock activation with given ID. Activation moves to ACTIVE state, only activations in BLOCKED state
     * can be blocked. Attempt to unblock an activation in incorrect state results in exception.
     *
     * @param request Unblock activation request object.
     * @return Unblock activation response.
     * @throws Exception In case of a business logic error.
     */
    UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception;

    /**
     * Return the data for the vault unlock request. Part of the vault unlock process is performing a signature
     * validation - the rules for blocking activation and counter increment are therefore similar as for the
     * {@link PowerAuthService#verifySignature(VerifySignatureRequest)} method. For vaultUnlock, however,
     * counter is incremented by 2 - one for signature validation, second for the transport key derivation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Vault unlock request object.
     * @return Vault unlock response.
     * @throws Exception In case of a business logic error.
     */
    VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception;

    /**
     * Validate incoming ECDSA signature for provided data using a public device key associated with given activation.
     * @param request Request for signature validation.
     * @return Response with the signature validation status.
     * @throws Exception In case of a business logic error.
     */
    VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws Exception;

    /**
     * Get records from the signature audit log.
     *
     * @param request Signature audit log request.
     * @return Signature audit log response.
     * @throws Exception In case of a business logic error.
     */
    SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws Exception;

    /**
     * Get activation history.
     *
     * @param request Signature audit log request.
     * @return Signature audit log response.
     * @throws Exception In case of a business logic error.
     */
    ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws Exception;

    /**
     * Get all applications in the system.
     *
     * @param request Application list request object.
     * @return Application list response.
     * @throws Exception In case of a business logic error.
     */
    GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws Exception;

    /**
     * Get application detail, including application version list.
     *
     * @param request Application detail request object.
     * @return Application detail response.
     * @throws Exception In case of a business logic error.
     */
    GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws Exception;

    /**
     * Get application detail, including application version list, based on the version app key.
     *
     * @param request Request object with version app key.
     * @return Application detail response.
     * @throws Exception In case of a business logic error.
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws Exception;

    /**
     * Create a new application with given name. Master key pair and default application version is automatically
     * generated when calling this method.
     *
     * @param request Create application request.
     * @return Created application information response.
     * @throws Exception In case of a business logic error.
     */
    CreateApplicationResponse createApplication(CreateApplicationRequest request) throws Exception;

    /**
     * Create a new application version with given name. Each application version has its own APPLICATION_KEY
     * and APPLICATION_SECRET values.
     *
     * @param request Application version create request object.
     * @return Application version create response.
     * @throws Exception In case of a business logic error.
     */
    CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws Exception;

    /**
     * Unsupport an application version. If an application is unsupported, it's APPLICATION_KEY and APPLICATION_SECRET
     * cannot be used for computing a signature.
     *
     * @param request Unsupport application version request.
     * @return Unsupport application version response.
     * @throws Exception In case of a business logic error.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws Exception;

    /**
     * Support an application version. If an application is supported, it's APPLICATION_KEY and APPLICATION_SECRET
     * can be used for computing a signature.
     *
     * @param request Support application version request.
     * @return Support application version response.
     * @throws Exception In case of a business logic error.
     */
    SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws Exception;

    /**
     * Create a new credentials for integration with given name. Automatically generates appropriate credentials.
     * @param request Request with integration name.
     * @return Newly created integration details.
     * @throws Exception In case of a business logic error.
     */
    CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws Exception;

    /**
     * Get the list of currently present integrations.
     * @param request Get integration list request.
     * @return List of currently present integrations.
     * @throws Exception In case of a business logic error.
     */
    GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws Exception;

    /**
     * Remove integration with given ID.
     * @param request Request with integration ID.
     * @return Removal status information.
     * @throws Exception In case of a business logic error.
     */
    RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws Exception;

    /**
     * Create a new callback URL for given application.
     * @param request Request with application ID and callback URL parameters.
     * @return New callback URL information.
     * @throws Exception In case of a business logic error.
     */
    CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws Exception;

    /**
     * Update callback URL for given application.
     * @param request Request with application ID and callback URL parameters.
     * @return New callback URL information.
     * @throws Exception In case of a business logic error.
     */
    UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws Exception;

    /**
     * Get the list of all callback URLs for given application.
     * @param request Request with application ID.
     * @return List of all callback URLs for given applications, ordered by name alphabetically.
     * @throws Exception In case of a business logic error.
     */
    GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws Exception;

    /**
     * Remove callback URL with given ID.
     * @param request Request with callback URL with given ID.
     * @return  Removal status information.
     * @throws Exception In case of a business logic error.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws Exception;

    /**
     * Creates a new token for simple token-based device authentication.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Request with information required to issue the token.
     * @return Response with the token information.
     * @throws Exception In case of a business logic error.
     */
    CreateTokenResponse createToken(CreateTokenRequest request) throws Exception;

    /**
     * Validate token during the simple token-based device authentication.
     * @param request Request with the token-based authentication credentials.
     * @return Response with the authentication result.
     * @throws Exception In case of a business logic error.
     */
    ValidateTokenResponse validateToken(ValidateTokenRequest request) throws Exception;

    /**
     * Remove token with provided ID.
     * @param request Request with token ID.
     * @return Response with the token removal result.
     * @throws Exception In case of a business logic error.
     */
    RemoveTokenResponse removeToken(RemoveTokenRequest request) throws Exception;

    /**
     * Get ECIES decyptor parameters for decryption of request on intermediate server.
     * @param request Request to get ECIES decryptor parameters.
     * @return ECIES decryptor parameters.
     * @throws Exception In case of a business logic error.
     */
    GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws Exception;

    /**
     * Start upgrade of activation to version 3.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws Exception In case of a business logic error.
     */
    StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws Exception;

    /**
     * Commit upgrade of activation to version 3.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws Exception In case of a business logic error.
     */
    CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws Exception;

    /**
     * Create recovery code.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws Exception In case of a business logic error.
     */
    CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws Exception;

    /**
     * Confirm recovery code, change its status from CREATED to ACTIVE.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws Exception In case of a business logic error.
     */
    ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws Exception;

    /**
     * Lookup recovery codes matching provided criteria.
     * @param request Lookup recovery codes request.
     * @return Lookup recover codes response.
     * @throws Exception In case of a business logic error.
     */
    LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws Exception;

    /**
     * Revoke specified recovery codes.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     * @throws Exception In case of a business logic error.
     */
    RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws Exception;

    /**
     * Create an activation using recovery code.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     * @throws Exception In case of a business logic error.
     */
    RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws Exception;

    /**
     * Get recovery configuration.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case of a business logic error.
     */
    GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws Exception;

    /**
     * Update recovery configuration.
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws Exception In case of a business logic error.
     */
    UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws Exception;

    /**
     * List activation flags.
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws Exception In case of a business logic error.
     */
    ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws Exception;

    /**
     * Add activation flags.
     * @param request Add activation flags request.
     * @return Create activation flags response.
     * @throws Exception In case of a business logic error.
     */
    AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws Exception;

    /**
     * Update activation flags.
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws Exception In case of a business logic error.
     */
    UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws Exception;

    /**
     * Remove activation flags.
     * @param request Remove activation flags request.
     * @return Delete activation flags response.
     * @throws Exception In case of a business logic error.
     */
    RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws Exception;


    /**
     * List application roles.
     * @param request List application roles request.
     * @return List application roles response.
     * @throws Exception In case of a business logic error.
     */
    ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws Exception;

    /**
     * Add application roles.
     * @param request Add application roles request.
     * @return Create application roles response.
     * @throws Exception In case of a business logic error.
     */
    AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws Exception;

    /**
     * Update application roles.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws Exception In case of a business logic error.
     */
    UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws Exception;

    /**
     * Remove application roles.
     * @param request Remove application roles request.
     * @return Delete application roles response.
     * @throws Exception In case of a business logic error.
     */
    RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws Exception;

    /**
     * Create a new operation.
     * @param request Create operation request.
     * @return Create operation response.
     * @throws Exception In case of a business logic error.
     */
    OperationDetailResponse createOperation(OperationCreateRequest request) throws Exception;

    /**
     * Get operation detail.
     * @param request Operation detail request.
     * @return Operation detail response.
     * @throws Exception In case of a business logic error.
     */
    OperationDetailResponse operationDetail(OperationDetailRequest request) throws Exception;

    /**
     * Get pending operation list for a user.
     * @param request Operation list request.
     * @return Operation list response.
     * @throws Exception In case of a business logic error.
     */
    OperationListResponse findPendingOperationsForUser(OperationListForUserRequest request) throws Exception;

    /**
     * Get complete operation list for a user.
     * @param request Operation list request.
     * @return Operation list response.
     * @throws Exception In case of a business logic error.
     */
    OperationListResponse findAllOperationsForUser(OperationListForUserRequest request) throws Exception;

    /**
     * Get operation list based on external operation ID.
     * @param request Operation by external ID request.
     * @return Operation list response.
     * @throws Exception In case of a business logic error.
     */
    OperationListResponse findAllOperationsByExternalId(OperationExtIdRequest request) throws Exception;

    /**
     * Cancel operation by ID.
     * @param request Operation cancel request.
     * @return Operation cancel response.
     * @throws Exception In case of a business logic error.
     */
    OperationDetailResponse cancelOperation(OperationCancelRequest request) throws Exception;

    /**
     * Approve operation by ID and other operation attributes.
     * @param request Operation approve request.
     * @return Operation approve response.
     * @throws Exception In case of a business logic error.
     */
    OperationUserActionResponse approveOperation(OperationApproveRequest request) throws Exception;

    /**
     * Simulate failed approval for operation by ID and other operation attributes.
     * This method is useful in case some other system (for example, the Internet banking)
     * needs to increase the approval failure count.
     *
     * @param request Operation failed approval request.
     * @return Operation failed approval response.
     * @throws Exception In case of a business logic error.
     */
    OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws Exception;

    /**
     * Reject operation by ID and other operation attributes.
     * @param request Operation reject request.
     * @return Operation reject response.
     * @throws Exception In case of a business logic error.
     */
    OperationUserActionResponse rejectOperation(OperationRejectRequest request) throws Exception;

    /**
     * Get all operation templates.
     * @return Operation templates.
     * @throws Exception In case of a business logic error.
     */
    OperationTemplateListResponse getAllTemplates() throws Exception;

    /**
     * Get operation template detail.
     * @param request Request with ID to fetch operation template detail for.
     * @return Operation template detail.
     * @throws Exception In case of a business logic error.
     */
    OperationTemplateDetailResponse getTemplateDetail(OperationTemplateDetailRequest request) throws Exception;

    /**
     * Create a new operation template.
     * @param request Parameters of a new operation template.
     * @return Operation template detail.
     * @throws Exception In case of a business logic error.
     */
    OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) throws Exception;

    /**
     * Update an existing operation.
     * @param request Parameters of an updated template with provided ID.
     * @return Operation template detail.
     * @throws Exception In case of a business logic error.
     */
    OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) throws Exception;

    /**
     * Remove operation template.
     * @param request Operation template with provided ID.
     * @throws Exception In case of a business logic error.
     */
    void removeOperationTemplate(OperationTemplateDeleteRequest request) throws Exception;

}
