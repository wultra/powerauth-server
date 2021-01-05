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
package io.getlime.security.powerauth.app.server.endpoint.v3;

import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

/**
 * Class implementing the SOAP service end-point.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Endpoint(value = "PowerAuth 3.0")
public class PowerAuthEndpoint {

    private static final String NAMESPACE_URI = "http://getlime.io/security/powerauth/v3";

    private PowerAuthService powerAuthService;

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    /**
     * Call {@link PowerAuthService#getSystemStatus(GetSystemStatusRequest)} method and
     * return the response.
     *
     * @param request Get system status request.
     * @return System status response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetSystemStatusRequest")
    @ResponsePayload
    public GetSystemStatusResponse getSystemStatus(@RequestPayload GetSystemStatusRequest request) throws Exception {
        return powerAuthService.getSystemStatus(request);
    }

    /**
     * Call {@link PowerAuthService#getErrorCodeList(GetErrorCodeListRequest)} method and
     * return the response.
     *
     * @param request Request for list of error codes indicating a language to be returned in.
     * @return Response with the list of error codes..
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetErrorCodeListRequest")
    @ResponsePayload
    public GetErrorCodeListResponse getErrorCodeList(@RequestPayload GetErrorCodeListRequest request) throws Exception {
        return powerAuthService.getErrorCodeList(request);
    }

    /**
     * Call {@link PowerAuthService#initActivation(InitActivationRequest)} method and
     * return the response.
     *
     * @param request Init activation request.
     * @return Init activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "InitActivationRequest")
    @ResponsePayload
    public InitActivationResponse initActivation(@RequestPayload InitActivationRequest request) throws Exception {
        return powerAuthService.initActivation(request);
    }

    /**
     * Call {@link PowerAuthService#prepareActivation(PrepareActivationRequest)} method and
     * return the response.
     *
     * @param request Prepare activation request.
     * @return Prepare activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "PrepareActivationRequest")
    @ResponsePayload
    public PrepareActivationResponse prepareActivation(@RequestPayload PrepareActivationRequest request) throws Exception {
        return powerAuthService.prepareActivation(request);
    }

    /**
     * Call {@link PowerAuthService#createActivation(CreateActivationRequest)} method and
     * return the response.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateActivationRequest")
    @ResponsePayload
    public CreateActivationResponse createActivation(@RequestPayload CreateActivationRequest request) throws Exception {
        return powerAuthService.createActivation(request);
    }

    /**
     * Call {@link PowerAuthService#updateActivationOtp(UpdateActivationOtpRequest)} method and return the response.
     *
     * @param request Update activation OTP request.
     * @return Update activation OTP activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UpdateActivationOtpRequest")
    @ResponsePayload
    public UpdateActivationOtpResponse updateActivationOtp(@RequestPayload UpdateActivationOtpRequest request) throws Exception {
        return powerAuthService.updateActivationOtp(request);
    }

    /**
     * Call {@link PowerAuthService#commitActivation(CommitActivationRequest)} method and
     * return the response.
     *
     * @param request Commit activation request.
     * @return Commit activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CommitActivationRequest")
    @ResponsePayload
    public CommitActivationResponse commitActivation(@RequestPayload CommitActivationRequest request) throws Exception {
        return powerAuthService.commitActivation(request);
    }

    /**
     * Call {@link PowerAuthService#getActivationStatus(GetActivationStatusRequest)} method and
     * return the response.
     *
     * @param request Activation status request.
     * @return Activation status response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetActivationStatusRequest")
    @ResponsePayload
    public GetActivationStatusResponse getActivationStatus(@RequestPayload GetActivationStatusRequest request) throws Exception {
        return powerAuthService.getActivationStatus(request);
    }

    /**
     * Call {@link PowerAuthService#removeActivation(RemoveActivationRequest)} method and
     * return the response.
     *
     * @param request Remove activation request.
     * @return Remove activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveActivationRequest")
    @ResponsePayload
    public RemoveActivationResponse removeActivation(@RequestPayload RemoveActivationRequest request) throws Exception {
        return powerAuthService.removeActivation(request);
    }

    /**
     * Call {@link PowerAuthService#getActivationListForUser(GetActivationListForUserRequest)} method and
     * return the response.
     *
     * @param request Activation list request.
     * @return Activation list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetActivationListForUserRequest")
    @ResponsePayload
    public GetActivationListForUserResponse getActivationListForUser(@RequestPayload GetActivationListForUserRequest request) throws Exception {
        return powerAuthService.getActivationListForUser(request);
    }

    /**
     * Call {@link PowerAuthService#lookupActivations(LookupActivationsRequest)} method and
     * return the response.
     *
     * @param request Activation lookup request.
     * @return Activation lookup response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "LookupActivationsRequest")
    @ResponsePayload
    public LookupActivationsResponse lookupActivations(@RequestPayload LookupActivationsRequest request) throws Exception {
        return powerAuthService.lookupActivations(request);
    }

    /**
     * Call {@link PowerAuthService#updateStatusForActivations(UpdateStatusForActivationsRequest)} method and
     * return the response.
     *
     * @param request Update status for activations request.
     * @return Update status for activations response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UpdateStatusForActivationsRequest")
    @ResponsePayload
    public UpdateStatusForActivationsResponse updateStatusForActivations(@RequestPayload UpdateStatusForActivationsRequest request) throws Exception {
        return powerAuthService.updateStatusForActivations(request);
    }

    /**
     * Call {@link PowerAuthService#verifySignature(VerifySignatureRequest)} method and
     * return the response.
     *
     * @param request Verify signature request.
     * @return Verify signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VerifySignatureRequest")
    @ResponsePayload
    public VerifySignatureResponse verifySignature(@RequestPayload VerifySignatureRequest request) throws Exception {
        return powerAuthService.verifySignature(request);
    }

    /**
     * Call {@link PowerAuthService#createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest)} method and
     * return the response.
     *
     * @param request Create personalized offline signature data request.
     * @return Create personalized offline signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreatePersonalizedOfflineSignaturePayloadRequest")
    @ResponsePayload
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(@RequestPayload CreatePersonalizedOfflineSignaturePayloadRequest request) throws Exception {
        return powerAuthService.createPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call {@link PowerAuthService#createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest)} method and
     * return the response.
     *
     * @param request Create non-personalized offline signature data request.
     * @return Create non-personalized offline signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateNonPersonalizedOfflineSignaturePayloadRequest")
    @ResponsePayload
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(@RequestPayload CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws Exception {
        return powerAuthService.createNonPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call {@link PowerAuthService#verifyOfflineSignature(VerifyOfflineSignatureRequest)} method and
     * return the response.
     *
     * @param request Verify offline signature request.
     * @return Verify offline signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VerifyOfflineSignatureRequest")
    @ResponsePayload
    public VerifyOfflineSignatureResponse verifyOfflineSignature(@RequestPayload VerifyOfflineSignatureRequest request) throws Exception {
        return powerAuthService.verifyOfflineSignature(request);
    }

    /**
     * Call {@link PowerAuthService#vaultUnlock(VaultUnlockRequest)} method and
     * return the response.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VaultUnlockRequest")
    @ResponsePayload
    public VaultUnlockResponse vaultUnlock(@RequestPayload VaultUnlockRequest request) throws Exception {
        return powerAuthService.vaultUnlock(request);
    }

    /**
     * Call {@link PowerAuthService#verifyECDSASignature(VerifyECDSASignatureRequest)} method and
     * return the response.
     *
     * @param request Verify ECDSA signature request.
     * @return Verify ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VerifyECDSASignatureRequest")
    @ResponsePayload
    public VerifyECDSASignatureResponse verifyECDSASignature(@RequestPayload VerifyECDSASignatureRequest request) throws Exception {
        return powerAuthService.verifyECDSASignature(request);
    }

    /**
     * Call {@link PowerAuthService#getSignatureAuditLog(SignatureAuditRequest)} method and
     * return the response.
     *
     * @param request Signature audit request.
     * @return Signature audit response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "SignatureAuditRequest")
    @ResponsePayload
    public SignatureAuditResponse getSignatureAuditLog(@RequestPayload SignatureAuditRequest request) throws Exception {
        return powerAuthService.getSignatureAuditLog(request);
    }

    /**
     * Call {@link PowerAuthService#getActivationHistory(ActivationHistoryRequest)} method and
     * return the response.
     *
     * @param request Activation history request.
     * @return Activation history response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "ActivationHistoryRequest")
    @ResponsePayload
    public ActivationHistoryResponse getActivationHistory(@RequestPayload ActivationHistoryRequest request) throws Exception {
        return powerAuthService.getActivationHistory(request);
    }

    /**
     * Call {@link PowerAuthService#blockActivation(BlockActivationRequest)} method and
     * return the response.
     *
     * @param request Block activation request.
     * @return Block activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "BlockActivationRequest")
    @ResponsePayload
    public BlockActivationResponse blockActivation(@RequestPayload BlockActivationRequest request) throws Exception {
        return powerAuthService.blockActivation(request);
    }

    /**
     * Call {@link PowerAuthService#unblockActivation(UnblockActivationRequest)} method and
     * return the response.
     *
     * @param request Unblock activation request.
     * @return Unblock activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UnblockActivationRequest")
    @ResponsePayload
    public UnblockActivationResponse unblockActivation(@RequestPayload UnblockActivationRequest request) throws Exception {
        return powerAuthService.unblockActivation(request);
    }

    /**
     * Call {@link PowerAuthService#getApplicationList(GetApplicationListRequest)} method and
     * return the response.
     *
     * @param request Application list request.
     * @return Application list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetApplicationListRequest")
    @ResponsePayload
    public GetApplicationListResponse getApplicationList(@RequestPayload GetApplicationListRequest request) throws Exception {
        return powerAuthService.getApplicationList(request);
    }

    /**
     * Call {@link PowerAuthService#getApplicationDetail(GetApplicationDetailRequest)} method and
     * return the response.
     *
     * @param request Application detail request.
     * @return Application detail response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetApplicationDetailRequest")
    @ResponsePayload
    public GetApplicationDetailResponse getApplicationDetail(@RequestPayload GetApplicationDetailRequest request) throws Exception {
        return powerAuthService.getApplicationDetail(request);
    }

    /**
     * Call {@link PowerAuthService#lookupApplicationByAppKey(LookupApplicationByAppKeyRequest)} method and
     * return the response.
     *
     * @param request Application lookup request.
     * @return Application lookup response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "LookupApplicationByAppKeyRequest")
    @ResponsePayload
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(@RequestPayload LookupApplicationByAppKeyRequest request) throws Exception {
        return powerAuthService.lookupApplicationByAppKey(request);
    }

    /**
     * Call {@link PowerAuthService#createApplication(CreateApplicationRequest)} method and
     * return the response.
     *
     * @param request Create application request.
     * @return Create application response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateApplicationRequest")
    @ResponsePayload
    public CreateApplicationResponse createApplication(@RequestPayload CreateApplicationRequest request) throws Exception {
        return powerAuthService.createApplication(request);
    }

    /**
     * Call {@link PowerAuthService#createApplicationVersion(CreateApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Create application version request.
     * @return Create application version response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateApplicationVersionRequest")
    @ResponsePayload
    public CreateApplicationVersionResponse createApplicationVersion(@RequestPayload CreateApplicationVersionRequest request) throws Exception {
        return powerAuthService.createApplicationVersion(request);
    }

    /**
     * Call {@link PowerAuthService#unsupportApplicationVersion(UnsupportApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Unsupport application version request.
     * @return Unsupport application version response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UnsupportApplicationVersionRequest")
    @ResponsePayload
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(@RequestPayload UnsupportApplicationVersionRequest request) throws Exception {
        return powerAuthService.unsupportApplicationVersion(request);
    }

    /**
     * Call {@link PowerAuthService#supportApplicationVersion(SupportApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Support application version request.
     * @return Support application version response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "SupportApplicationVersionRequest")
    @ResponsePayload
    public SupportApplicationVersionResponse supportApplicationVersion(@RequestPayload SupportApplicationVersionRequest request) throws Exception {
        return powerAuthService.supportApplicationVersion(request);
    }

    /**
     * Call {@link PowerAuthService#createIntegration(CreateIntegrationRequest)} method and
     * return the response.
     *
     * @param request Create integration request.
     * @return Create integration response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateIntegrationRequest")
    @ResponsePayload
    public CreateIntegrationResponse createIntegration(@RequestPayload CreateIntegrationRequest request) throws Exception {
        return powerAuthService.createIntegration(request);
    }

    /**
     * Call {@link PowerAuthService#getIntegrationList(GetIntegrationListRequest)} method and
     * return the response.
     *
     * @param request Get integration list request.
     * @return Get integration list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetIntegrationListRequest")
    @ResponsePayload
    public GetIntegrationListResponse getIntegrationList(@RequestPayload GetIntegrationListRequest request) throws Exception {
        return powerAuthService.getIntegrationList(request);
    }

    /**
     * Call {@link PowerAuthService#removeIntegration(RemoveIntegrationRequest)}  method and
     * return the response.
     *
     * @param request Remove integration request.
     * @return Remove integration response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveIntegrationRequest")
    @ResponsePayload
    public RemoveIntegrationResponse removeIntegration(@RequestPayload RemoveIntegrationRequest request) throws Exception {
        return powerAuthService.removeIntegration(request);
    }

    /**
     * Call {@link PowerAuthService#createCallbackUrl(CreateCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Create callback UR: request.
     * @return Create callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateCallbackUrlRequest")
    @ResponsePayload
    public CreateCallbackUrlResponse updateCallbackUrl(@RequestPayload CreateCallbackUrlRequest request) throws Exception {
        return powerAuthService.createCallbackUrl(request);
    }

    /**
     * Call {@link PowerAuthService#updateCallbackUrl(UpdateCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Update callback UR: request.
     * @return Update callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UpdateCallbackUrlRequest")
    @ResponsePayload
    public UpdateCallbackUrlResponse updateCallbackUrl(@RequestPayload UpdateCallbackUrlRequest request) throws Exception {
        return powerAuthService.updateCallbackUrl(request);
    }

    /**
     * Call {@link PowerAuthService#getCallbackUrlList(GetCallbackUrlListRequest)}  method and
     * return the response.
     *
     * @param request Get callback URL list request.
     * @return Get callback URL list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetCallbackUrlListRequest")
    @ResponsePayload
    public GetCallbackUrlListResponse getCallbackUrlList(@RequestPayload GetCallbackUrlListRequest request) throws Exception {
        return powerAuthService.getCallbackUrlList(request);
    }

    /**
     * Call {@link PowerAuthService#removeCallbackUrl(RemoveCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Remove callback URL request.
     * @return Remove callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveCallbackUrlRequest")
    @ResponsePayload
    public RemoveCallbackUrlResponse removeCallbackUrl(@RequestPayload RemoveCallbackUrlRequest request) throws Exception {
        return powerAuthService.removeCallbackUrl(request);
    }

    /**
     * Call {@link PowerAuthService#createToken(CreateTokenRequest)}  method and
     * return the response.
     *
     * @param request Create a new token.
     * @return Get response with the new token.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateTokenRequest")
    @ResponsePayload
    public CreateTokenResponse createToken(@RequestPayload CreateTokenRequest request) throws Exception {
        return powerAuthService.createToken(request);
    }

    /**
     * Call {@link PowerAuthService#validateToken(ValidateTokenRequest)} method and
     * return the response.
     *
     * @param request Validate token during authentication.
     * @return Response with the token validation result.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "ValidateTokenRequest")
    @ResponsePayload
    public ValidateTokenResponse validateToken(@RequestPayload ValidateTokenRequest request) throws Exception {
        return powerAuthService.validateToken(request);
    }

    /**
     * Call {@link PowerAuthService#removeToken(RemoveTokenRequest)} method and
     * return the response.
     *
     * @param request Remove token with given ID.
     * @return Response with the token removal result.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveTokenRequest")
    @ResponsePayload
    public RemoveTokenResponse removeToken(@RequestPayload RemoveTokenRequest request) throws Exception {
        return powerAuthService.removeToken(request);
    }

    /**
     * Call {@link PowerAuthService#getEciesDecryptor(GetEciesDecryptorRequest)} method and
     * return the response.
     *
     * @param request Get ECIES decryptor parameters for given request.
     * @return Response with ECIES decryptor parameters.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetEciesDecryptorRequest")
    @ResponsePayload
    public GetEciesDecryptorResponse getEciesDecryptor(@RequestPayload GetEciesDecryptorRequest request) throws Exception {
        return powerAuthService.getEciesDecryptor(request);
    }

    /**
     * Call {@link PowerAuthService#startUpgrade(StartUpgradeRequest)} method and
     * return the response.
     *
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "StartUpgradeRequest")
    @ResponsePayload
    public StartUpgradeResponse startUpgrade(@RequestPayload StartUpgradeRequest request) throws Exception {
        return powerAuthService.startUpgrade(request);
    }

    /**
     * Call {@link PowerAuthService#commitUpgrade(CommitUpgradeRequest)} method and
     * return the response.
     *
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CommitUpgradeRequest")
    @ResponsePayload
    public CommitUpgradeResponse commitUpgrade(@RequestPayload CommitUpgradeRequest request) throws Exception {
        return powerAuthService.commitUpgrade(request);
    }

    /**
     * Call {@link PowerAuthService#createRecoveryCode(CreateRecoveryCodeRequest)} method and
     * return the response.
     *
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateRecoveryCodeRequest")
    @ResponsePayload
    public CreateRecoveryCodeResponse createRecoveryCodeForUser(@RequestPayload CreateRecoveryCodeRequest request) throws Exception {
        return powerAuthService.createRecoveryCode(request);
    }

    /**
     * Call {@link PowerAuthService#confirmRecoveryCode(ConfirmRecoveryCodeRequest)} method and
     * return the response.
     *
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "ConfirmRecoveryCodeRequest")
    @ResponsePayload
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(@RequestPayload ConfirmRecoveryCodeRequest request) throws Exception {
        return powerAuthService.confirmRecoveryCode(request);
    }

    /**
     * Call {@link PowerAuthService#lookupRecoveryCodes(LookupRecoveryCodesRequest)} method and
     * return the response.
     *
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "LookupRecoveryCodesRequest")
    @ResponsePayload
    public LookupRecoveryCodesResponse lookupRecoveryCodes(@RequestPayload LookupRecoveryCodesRequest request) throws Exception {
        return powerAuthService.lookupRecoveryCodes(request);
    }

    /**
     * Call {@link PowerAuthService#revokeRecoveryCodes(RevokeRecoveryCodesRequest)} method and
     * return the response.
     *
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RevokeRecoveryCodesRequest")
    @ResponsePayload
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(@RequestPayload RevokeRecoveryCodesRequest request) throws Exception {
        return powerAuthService.revokeRecoveryCodes(request);
    }

    /**
     * Call {@link PowerAuthService#createActivationUsingRecoveryCode(RecoveryCodeActivationRequest)} method and
     * return the response.
     *
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery codes response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RecoveryCodeActivationRequest")
    @ResponsePayload
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(@RequestPayload RecoveryCodeActivationRequest request) throws Exception {
        return powerAuthService.createActivationUsingRecoveryCode(request);
    }

    /**
     * Call {@link PowerAuthService#getRecoveryConfig(GetRecoveryConfigRequest)} method and
     * return the response.
     *
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetRecoveryConfigRequest")
    @ResponsePayload
    public GetRecoveryConfigResponse getRecoveryConfig(@RequestPayload GetRecoveryConfigRequest request) throws Exception {
        return powerAuthService.getRecoveryConfig(request);
    }

    /**
     * Call {@link PowerAuthService#updateRecoveryConfig(UpdateRecoveryConfigRequest)} method and
     * return the response.
     *
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UpdateRecoveryConfigRequest")
    @ResponsePayload
    public UpdateRecoveryConfigResponse updateRecoveryConfig(@RequestPayload UpdateRecoveryConfigRequest request) throws Exception {
        return powerAuthService.updateRecoveryConfig(request);
    }

    /**
     * Call {@link PowerAuthService#listActivationFlags(ListActivationFlagsRequest)} method and
     * return the response.
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "ListActivationFlagsRequest")
    @ResponsePayload
    public ListActivationFlagsResponse listActivationFlags(@RequestPayload ListActivationFlagsRequest request) throws Exception {
        return powerAuthService.listActivationFlags(request);
    }

    /**
     * Call {@link PowerAuthService#addActivationFlags(AddActivationFlagsRequest)} method and
     * return the response.
     * @param request Create activation flags request.
     * @return Create activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "AddActivationFlagsRequest")
    @ResponsePayload
    public AddActivationFlagsResponse addActivationFlags(@RequestPayload AddActivationFlagsRequest request) throws Exception {
        return powerAuthService.addActivationFlags(request);
    }

    /**
     * Call {@link PowerAuthService#updateActivationFlags(UpdateActivationFlagsRequest)} method and
     * return the response.
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UpdateActivationFlagsRequest")
    @ResponsePayload
    public UpdateActivationFlagsResponse updateActivationFlags(@RequestPayload UpdateActivationFlagsRequest request) throws Exception {
        return powerAuthService.updateActivationFlags(request);
    }

    /**
     * Call {@link PowerAuthService#removeActivationFlags(RemoveActivationFlagsRequest)} method and
     * return the response.
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveActivationFlagsRequest")
    @ResponsePayload
    public RemoveActivationFlagsResponse removeActivationFlags(@RequestPayload RemoveActivationFlagsRequest request) throws Exception {
        return powerAuthService.removeActivationFlags(request);
    }

    /**
     * Call {@link PowerAuthService#listApplicationRoles(ListApplicationRolesRequest)} method and
     * return the response.
     * @param request List application roles request.
     * @return List application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "ListApplicationRolesRequest")
    @ResponsePayload
    public ListApplicationRolesResponse listApplicationRoles(@RequestPayload ListApplicationRolesRequest request) throws Exception {
        return powerAuthService.listApplicationRoles(request);
    }

    /**
     * Call {@link PowerAuthService#addApplicationRoles(AddApplicationRolesRequest)} method and
     * return the response.
     * @param request Create application roles request.
     * @return Create application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "AddApplicationRolesRequest")
    @ResponsePayload
    public AddApplicationRolesResponse addApplicationRoles(@RequestPayload AddApplicationRolesRequest request) throws Exception {
        return powerAuthService.addApplicationRoles(request);
    }

    /**
     * Call {@link PowerAuthService#updateApplicationRoles(UpdateApplicationRolesRequest)} method and
     * return the response.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UpdateApplicationRolesRequest")
    @ResponsePayload
    public UpdateApplicationRolesResponse updateApplicationRoles(@RequestPayload UpdateApplicationRolesRequest request) throws Exception {
        return powerAuthService.updateApplicationRoles(request);
    }

    /**
     * Call {@link PowerAuthService#removeApplicationRoles(RemoveApplicationRolesRequest)} method and
     * return the response.
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveApplicationRolesRequest")
    @ResponsePayload
    public RemoveApplicationRolesResponse removeApplicationRoles(@RequestPayload RemoveApplicationRolesRequest request) throws Exception {
        return powerAuthService.removeApplicationRoles(request);
    }

}
