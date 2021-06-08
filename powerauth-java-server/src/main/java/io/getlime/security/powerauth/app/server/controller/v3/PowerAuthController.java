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
package io.getlime.security.powerauth.app.server.controller.v3;

import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Class implementing the RESTful controller for PowerAuth service.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("restControllerV3")
@RequestMapping(value = "/rest/v3")
@Tag(name = "PowerAuth Controller V3")
public class PowerAuthController {

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
    @RequestMapping(value = "/status", method = RequestMethod.POST)
    public ObjectResponse<GetSystemStatusResponse> getSystemStatus(@RequestBody ObjectRequest<GetSystemStatusRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getSystemStatus(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getErrorCodeList(GetErrorCodeListRequest)} method and
     * return the response.
     *
     * @param request Request for list of error codes indicating a language to be returned in.
     * @return Response with the list of error codes..
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/error/list", method = RequestMethod.POST)
    public ObjectResponse<GetErrorCodeListResponse> getErrorCodeList(@RequestBody ObjectRequest<GetErrorCodeListRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getErrorCodeList(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#initActivation(InitActivationRequest)} method and
     * return the response.
     *
     * @param request Init activation request.
     * @return Init activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/init", method = RequestMethod.POST)
    public ObjectResponse<InitActivationResponse> initActivation(@RequestBody ObjectRequest<InitActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.initActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#prepareActivation(PrepareActivationRequest)} method and
     * return the response.
     *
     * @param request Prepare activation request.
     * @return Prepare activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/prepare", method = RequestMethod.POST)
    public ObjectResponse<PrepareActivationResponse> prepareActivation(@RequestBody ObjectRequest<PrepareActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.prepareActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createActivation(CreateActivationRequest)}  method and
     * return the response.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/create", method = RequestMethod.POST)
    public ObjectResponse<CreateActivationResponse> createActivation(@RequestBody ObjectRequest<CreateActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateActivationOtp(UpdateActivationOtpRequest)} method and return the response.
     * @param request Update activation OTP request.
     * @return Update activation OTP response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/otp/update", method = RequestMethod.POST)
    public ObjectResponse<UpdateActivationOtpResponse> updateActivationOtp(@RequestBody ObjectRequest<UpdateActivationOtpRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateActivationOtp(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#commitActivation(CommitActivationRequest)} method and
     * return the response.
     *
     * @param request Commit activation request.
     * @return Commit activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/commit", method = RequestMethod.POST)
    public ObjectResponse<CommitActivationResponse> commitActivation(@RequestBody ObjectRequest<CommitActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.commitActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getActivationStatus(GetActivationStatusRequest)} method and
     * return the response.
     *
     * @param request Activation status request.
     * @return Activation status response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/status", method = RequestMethod.POST)
    public ObjectResponse<GetActivationStatusResponse> getActivationStatus(@RequestBody ObjectRequest<GetActivationStatusRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getActivationStatus(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeActivation(RemoveActivationRequest)} method and
     * return the response.
     *
     * @param request Remove activation request.
     * @return Remove activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/remove", method = RequestMethod.POST)
    public ObjectResponse<RemoveActivationResponse> removeActivation(@RequestBody ObjectRequest<RemoveActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.removeActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getActivationListForUser(GetActivationListForUserRequest)} method and
     * return the response.
     *
     * @param request Activation list request.
     * @return Activation list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/list", method = RequestMethod.POST)
    public ObjectResponse<GetActivationListForUserResponse> getActivationListForUser(@RequestBody ObjectRequest<GetActivationListForUserRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getActivationListForUser(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#lookupActivations(LookupActivationsRequest)} method and
     * return the response.
     *
     * @param request Lookup activations request.
     * @return Lookup activations response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/lookup", method = RequestMethod.POST)
    public ObjectResponse<LookupActivationsResponse> lookupActivations(@RequestBody ObjectRequest<LookupActivationsRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.lookupActivations(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateStatusForActivations(UpdateStatusForActivationsRequest)} method and
     * return the response.
     *
     * @param request Update status for activations request.
     * @return Update status for activations response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/status/update", method = RequestMethod.POST)
    public ObjectResponse<UpdateStatusForActivationsResponse> updateStatusForActivations(@RequestBody ObjectRequest<UpdateStatusForActivationsRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateStatusForActivations(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#verifySignature(VerifySignatureRequest)} method and
     * return the response.
     *
     * @param request Verify signature request.
     * @return Verify signature response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/signature/verify", method = RequestMethod.POST)
    public ObjectResponse<VerifySignatureResponse> verifySignature(@RequestBody ObjectRequest<VerifySignatureRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.verifySignature(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest)} method and
     * return the response.
     *
     * @param request Create personalized offline signature data request.
     * @return Create personalized offline signature data response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/signature/offline/personalized/create", method = RequestMethod.POST)
    public ObjectResponse<CreatePersonalizedOfflineSignaturePayloadResponse> createPersonalizedOfflineSignaturePayload(@RequestBody ObjectRequest<CreatePersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createPersonalizedOfflineSignaturePayload(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest)} method and
     * return the response.
     *
     * @param request Create non-personalized offline signature data request.
     * @return Create non-personalized offline signature data response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/signature/offline/non-personalized/create", method = RequestMethod.POST)
    public ObjectResponse<CreateNonPersonalizedOfflineSignaturePayloadResponse> createNonPersonalizedOfflineSignaturePayload(@RequestBody ObjectRequest<CreateNonPersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createNonPersonalizedOfflineSignaturePayload(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#verifyOfflineSignature(VerifyOfflineSignatureRequest)} method and
     * return the response.
     *
     * @param request Verify offline signature request.
     * @return Verify offline signature response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/signature/offline/verify", method = RequestMethod.POST)
    public ObjectResponse<VerifyOfflineSignatureResponse> verifyOfflineSignature(@RequestBody ObjectRequest<VerifyOfflineSignatureRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.verifyOfflineSignature(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#vaultUnlock(VaultUnlockRequest)} method and
     * return the response.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/vault/unlock", method = RequestMethod.POST)
    public ObjectResponse<VaultUnlockResponse> vaultUnlock(@RequestBody ObjectRequest<VaultUnlockRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.vaultUnlock(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#verifyECDSASignature(VerifyECDSASignatureRequest)} method and
     * return the response.
     *
     * @param request Verify ECDSA signature request.
     * @return Verify ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/signature/ecdsa/verify", method = RequestMethod.POST)
    public ObjectResponse<VerifyECDSASignatureResponse> verifyECDSASignature(@RequestBody ObjectRequest<VerifyECDSASignatureRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.verifyECDSASignature(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getSignatureAuditLog(SignatureAuditRequest)} method and
     * return the response.
     *
     * @param request Signature audit request.
     * @return Signature audit response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/signature/list", method = RequestMethod.POST)
    public ObjectResponse<SignatureAuditResponse> getSignatureAuditLog(@RequestBody ObjectRequest<SignatureAuditRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getSignatureAuditLog(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getActivationHistory(ActivationHistoryRequest)} method and
     * return the response.
     *
     * @param request Activation history request.
     * @return Activation history response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/history", method = RequestMethod.POST)
    public ObjectResponse<ActivationHistoryResponse> getActivationHistory(@RequestBody ObjectRequest<ActivationHistoryRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getActivationHistory(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#blockActivation(BlockActivationRequest)} method and
     * return the response.
     *
     * @param request Block activation request.
     * @return Block activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/block", method = RequestMethod.POST)
    public ObjectResponse<BlockActivationResponse> blockActivation(@RequestBody ObjectRequest<BlockActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.blockActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#unblockActivation(UnblockActivationRequest)} method and
     * return the response.
     *
     * @param request Unblock activation request.
     * @return Unblock activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/unblock", method = RequestMethod.POST)
    public ObjectResponse<UnblockActivationResponse> unblockActivation(@RequestBody ObjectRequest<UnblockActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.unblockActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getApplicationList(GetApplicationListRequest)} method and
     * return the response.
     *
     * @param request Application list request.
     * @return Application list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/list", method = RequestMethod.POST)
    public ObjectResponse<GetApplicationListResponse> getApplicationList(@RequestBody ObjectRequest<GetApplicationListRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getApplicationList(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getApplicationDetail(GetApplicationDetailRequest)} method and
     * return the response.
     *
     * @param request Application detail request.
     * @return Application detail response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/detail", method = RequestMethod.POST)
    public ObjectResponse<GetApplicationDetailResponse> getApplicationDetail(@RequestBody ObjectRequest<GetApplicationDetailRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getApplicationDetail(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#lookupApplicationByAppKey(LookupApplicationByAppKeyRequest)} method and
     * return the response.
     *
     * @param request Application detail request.
     * @return Application detail response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/detail/version", method = RequestMethod.POST)
    public ObjectResponse<LookupApplicationByAppKeyResponse> lookupApplicationByAppKey(@RequestBody ObjectRequest<LookupApplicationByAppKeyRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.lookupApplicationByAppKey(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createApplication(CreateApplicationRequest)} method and
     * return the response.
     *
     * @param request Create application request.
     * @return Create application response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/create", method = RequestMethod.POST)
    public ObjectResponse<CreateApplicationResponse> createApplication(@RequestBody ObjectRequest<CreateApplicationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createApplication(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createApplicationVersion(CreateApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Create application version request.
     * @return Create application version response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/version/create", method = RequestMethod.POST)
    public ObjectResponse<CreateApplicationVersionResponse> createApplicationVersion(@RequestBody ObjectRequest<CreateApplicationVersionRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createApplicationVersion(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#unsupportApplicationVersion(UnsupportApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Unsupport application version request.
     * @return Unsupport application version response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/version/unsupport", method = RequestMethod.POST)
    public ObjectResponse<UnsupportApplicationVersionResponse> unsupportApplicationVersion(@RequestBody ObjectRequest<UnsupportApplicationVersionRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.unsupportApplicationVersion(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#supportApplicationVersion(SupportApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Support application version request.
     * @return Support application version response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/version/support", method = RequestMethod.POST)
    public ObjectResponse<SupportApplicationVersionResponse> supportApplicationVersion(@RequestBody ObjectRequest<SupportApplicationVersionRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.supportApplicationVersion(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createIntegration(CreateIntegrationRequest)} method and
     * return the response.
     *
     * @param request Create integration request.
     * @return Create integration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/integration/create", method = RequestMethod.POST)
    public ObjectResponse<CreateIntegrationResponse> createIntegration(@RequestBody ObjectRequest<CreateIntegrationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createIntegration(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getIntegrationList(GetIntegrationListRequest)} method and
     * return the response.
     *
     * @return Get integration list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/integration/list", method = RequestMethod.POST)
    public ObjectResponse<GetIntegrationListResponse> getIntegrationList(@RequestBody ObjectRequest<GetIntegrationListRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getIntegrationList(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeIntegration(RemoveIntegrationRequest)} method and
     * return the response.
     *
     * @param request Remove integration request.
     * @return Remove integration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/integration/remove", method = RequestMethod.POST)
    public ObjectResponse<RemoveIntegrationResponse> removeIntegration(@RequestBody ObjectRequest<RemoveIntegrationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.removeIntegration(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createCallbackUrl(CreateCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Create callback URL request.
     * @return Create callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/callback/create", method = RequestMethod.POST)
    public ObjectResponse<CreateCallbackUrlResponse> createCallbackUrl(@RequestBody ObjectRequest<CreateCallbackUrlRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createCallbackUrl(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateCallbackUrl(UpdateCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Update callback URL request.
     * @return Update callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/callback/update", method = RequestMethod.POST)
    public ObjectResponse<UpdateCallbackUrlResponse> updateCallbackUrl(@RequestBody ObjectRequest<UpdateCallbackUrlRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateCallbackUrl(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getCallbackUrlList(GetCallbackUrlListRequest)} method and
     * return the response.
     *
     * @param request Get callback URL list request.
     * @return Get callback URL list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/callback/list", method = RequestMethod.POST)
    public ObjectResponse<GetCallbackUrlListResponse> getCallbackUrlList(@RequestBody ObjectRequest<GetCallbackUrlListRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getCallbackUrlList(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeCallbackUrl(RemoveCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Remove callback URL request.
     * @return Remove callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/callback/remove", method = RequestMethod.POST)
    public ObjectResponse<RemoveCallbackUrlResponse> removeCallbackUrl(@RequestBody ObjectRequest<RemoveCallbackUrlRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.removeCallbackUrl(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createToken(CreateTokenRequest)} method and
     * return the response.
     *
     * @param request Create a new token for a simple token-based authentication.
     * @return Response with the new token information.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/token/create", method = RequestMethod.POST)
    public ObjectResponse<CreateTokenResponse> createToken(@RequestBody ObjectRequest<CreateTokenRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createToken(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#validateToken(ValidateTokenRequest)} method and
     * return the response.
     *
     * @param request Validate token during token-based authentication.
     * @return Token validation result.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/token/validate", method = RequestMethod.POST)
    public ObjectResponse<ValidateTokenResponse> validateToken(@RequestBody ObjectRequest<ValidateTokenRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.validateToken(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeToken(RemoveTokenRequest)} method and
     * return the response.
     *
     * @param request Remove token with given token ID.
     * @return Token removal result.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/token/remove", method = RequestMethod.POST)
    public ObjectResponse<RemoveTokenResponse> removeToken(@RequestBody ObjectRequest<RemoveTokenRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.removeToken(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getEciesDecryptor(GetEciesDecryptorRequest)} method and
     * return the response.
     *
     * @param request Get ECIES decryptor parameters for given request.
     * @return Response with ECIES decryptor parameters.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/ecies/decryptor", method = RequestMethod.POST)
    public ObjectResponse<GetEciesDecryptorResponse> getEciesDecryptor(@RequestBody ObjectRequest<GetEciesDecryptorRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getEciesDecryptor(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#startUpgrade(StartUpgradeRequest)} method and
     * return the response.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/upgrade/start", method = RequestMethod.POST)
    public ObjectResponse<StartUpgradeResponse> startUpgrade(@RequestBody ObjectRequest<StartUpgradeRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.startUpgrade(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#commitUpgrade(CommitUpgradeRequest)} method and
     * return the response.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/upgrade/commit", method = RequestMethod.POST)
    public ObjectResponse<CommitUpgradeResponse> commitUpgrade(@RequestBody ObjectRequest<CommitUpgradeRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.commitUpgrade(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createRecoveryCode(CreateRecoveryCodeRequest)} method and
     * return the response.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/create", method = RequestMethod.POST)
    public ObjectResponse<CreateRecoveryCodeResponse> createRecoveryCodeForUser(@RequestBody ObjectRequest<CreateRecoveryCodeRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#confirmRecoveryCode(ConfirmRecoveryCodeRequest)} method and
     * return the response.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/confirm", method = RequestMethod.POST)
    public ObjectResponse<ConfirmRecoveryCodeResponse> confirmRecoveryCode(@RequestBody ObjectRequest<ConfirmRecoveryCodeRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.confirmRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#lookupRecoveryCodes(LookupRecoveryCodesRequest)} method and
     * return the response.
     * @param request Lookup recovery codes request.
     * @return Lookup recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/lookup", method = RequestMethod.POST)
    public ObjectResponse<LookupRecoveryCodesResponse> lookupRecoveryCodesRequest(@RequestBody ObjectRequest<LookupRecoveryCodesRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.lookupRecoveryCodes(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#revokeRecoveryCodes(RevokeRecoveryCodesRequest)} method and
     * return the response.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/revoke", method = RequestMethod.POST)
    public ObjectResponse<RevokeRecoveryCodesResponse> revokeRecoveryCodesRequest(@RequestBody ObjectRequest<RevokeRecoveryCodesRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.revokeRecoveryCodes(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createActivationUsingRecoveryCode(RecoveryCodeActivationRequest)} method and
     * return the response.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/recovery/create", method = RequestMethod.POST)
    public ObjectResponse<RecoveryCodeActivationResponse> createActivationUsingRecoveryCode(@RequestBody ObjectRequest<RecoveryCodeActivationRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createActivationUsingRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getRecoveryConfig(GetRecoveryConfigRequest)} method and
     * return the response.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/config/detail", method = RequestMethod.POST)
    public ObjectResponse<GetRecoveryConfigResponse> getRecoveryConfig(@RequestBody ObjectRequest<GetRecoveryConfigRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getRecoveryConfig(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateRecoveryConfig(UpdateRecoveryConfigRequest)} method and
     * return the response.
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/config/update", method = RequestMethod.POST)
    public ObjectResponse<UpdateRecoveryConfigResponse> updateRecoveryConfig(@RequestBody ObjectRequest<UpdateRecoveryConfigRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateRecoveryConfig(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#listActivationFlags(ListActivationFlagsRequest)} method and
     * return the response.
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/list", method = RequestMethod.POST)
    public ObjectResponse<ListActivationFlagsResponse> listActivationFlags(@RequestBody ObjectRequest<ListActivationFlagsRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.listActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#addActivationFlags(AddActivationFlagsRequest)} method and
     * return the response.
     * @param request Add activation flags request.
     * @return Add activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/create", method = RequestMethod.POST)
    public ObjectResponse<AddActivationFlagsResponse> addActivationFlags(@RequestBody ObjectRequest<AddActivationFlagsRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.addActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateActivationFlags(UpdateActivationFlagsRequest)} method and
     * return the response.
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/update", method = RequestMethod.POST)
    public ObjectResponse<UpdateActivationFlagsResponse> updateActivationFlags(@RequestBody ObjectRequest<UpdateActivationFlagsRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeActivationFlags(RemoveActivationFlagsRequest)} method and
     * return the response.
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/remove", method = RequestMethod.POST)
    public ObjectResponse<RemoveActivationFlagsResponse> removeActivationFlags(@RequestBody ObjectRequest<RemoveActivationFlagsRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.removeActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#listApplicationRoles(ListApplicationRolesRequest)} method and
     * return the response.
     * @param request List application roles request.
     * @return List application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/list", method = RequestMethod.POST)
    public ObjectResponse<ListApplicationRolesResponse> listApplicationRoles(@RequestBody ObjectRequest<ListApplicationRolesRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.listApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#addApplicationRoles(AddApplicationRolesRequest)} method and
     * return the response.
     * @param request Create application roles request.
     * @return Create application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/create", method = RequestMethod.POST)
    public ObjectResponse<AddApplicationRolesResponse> addApplicationRoles(@RequestBody ObjectRequest<AddApplicationRolesRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.addApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateApplicationRoles(UpdateApplicationRolesRequest)} method and
     * return the response.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/update", method = RequestMethod.POST)
    public ObjectResponse<UpdateApplicationRolesResponse> updateApplicationRoles(@RequestBody ObjectRequest<UpdateApplicationRolesRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeApplicationRoles(RemoveApplicationRolesRequest)} method and
     * return the response.
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/remove", method = RequestMethod.POST)
    public ObjectResponse<RemoveApplicationRolesResponse> removeApplicationRoles(@RequestBody ObjectRequest<RemoveApplicationRolesRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.removeApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createOperation(OperationCreateRequest)} method and
     * return the response.
     * @param request Create a new operation request.
     * @return Create operation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/create", method = RequestMethod.POST)
    public ObjectResponse<OperationDetailResponse> createOperation(@RequestBody ObjectRequest<OperationCreateRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createOperation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#operationDetail(OperationDetailRequest)} method and
     * return the response.
     * @param request Get operation request.
     * @return Get operation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/detail", method = RequestMethod.POST)
    public ObjectResponse<OperationDetailResponse> operationDetail(@RequestBody ObjectRequest<OperationDetailRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.operationDetail(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#findAllOperationsForUser(OperationListForUserRequest)} method and
     * return the response.
     * @param request Get operation list request.
     * @return Get operation list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/list", method = RequestMethod.POST)
    public ObjectResponse<OperationListResponse> operationList(@RequestBody ObjectRequest<OperationListForUserRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.findAllOperationsForUser(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#findPendingOperationsForUser(OperationListForUserRequest)} method and
     * return the response.
     * @param request Get pending operation list request.
     * @return Get pending operation list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/list/pending", method = RequestMethod.POST)
    public ObjectResponse<OperationListResponse> pendingOperationList(@RequestBody ObjectRequest<OperationListForUserRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.findPendingOperationsForUser(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#findAllOperationsByExternalId(OperationExtIdRequest)} method and
     * return the response.
     * @param request Get operations based on external ID request.
     * @return Get operation list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/list/external", method = RequestMethod.POST)
    public ObjectResponse<OperationListResponse> findAllOperationsByExternalId(@RequestBody ObjectRequest<OperationExtIdRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.findAllOperationsByExternalId(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#cancelOperation(OperationCancelRequest)} method and
     * return the response.
     * @param request Cancel operation request.
     * @return Cancel operation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/cancel", method = RequestMethod.POST)
    public ObjectResponse<OperationDetailResponse> cancelOperation(@RequestBody ObjectRequest<OperationCancelRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.cancelOperation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#approveOperation(OperationApproveRequest)} method and
     * return the response.
     * @param request Approve operation request.
     * @return Approve operation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/approve", method = RequestMethod.POST)
    public ObjectResponse<OperationUserActionResponse> approveOperation(@RequestBody ObjectRequest<OperationApproveRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.approveOperation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#failApprovalOperation(OperationFailApprovalRequest)}  method and
     * return the response.
     * @param request Fail approval operation request.
     * @return Fail approval operation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/approve/fail", method = RequestMethod.POST)
    public ObjectResponse<OperationUserActionResponse> failApprovalOperation(@RequestBody ObjectRequest<OperationFailApprovalRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.failApprovalOperation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#rejectOperation(OperationRejectRequest)} method and
     * return the response.
     * @param request Reject operation request.
     * @return Reject operation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/reject", method = RequestMethod.POST)
    public ObjectResponse<OperationUserActionResponse> rejectOperation(@RequestBody ObjectRequest<OperationRejectRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.rejectOperation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getAllTemplates()} method and
     * return the response.
     * @return Get operation templates response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/template/list", method = RequestMethod.POST)
    public ObjectResponse<OperationTemplateListResponse> getOperationTemplateList() throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getAllTemplates());
    }

    /**
     * Call {@link PowerAuthService#getTemplateDetail(OperationTemplateDetailRequest)} method and
     * return the response.
     * @param request Get operation template detail request.
     * @return Get operation template detail response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/template/detail", method = RequestMethod.POST)
    public ObjectResponse<OperationTemplateDetailResponse> getOperationTemplateDetail(@RequestBody ObjectRequest<OperationTemplateDetailRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.getTemplateDetail(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createOperationTemplate(OperationTemplateCreateRequest)} method and
     * return the response.
     * @param request Create operation template request.
     * @return Created operation template detail response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/template/create", method = RequestMethod.POST)
    public ObjectResponse<OperationTemplateDetailResponse> createOperationTemplate(@RequestBody ObjectRequest<OperationTemplateCreateRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.createOperationTemplate(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateOperationTemplate(OperationTemplateUpdateRequest)} method and
     * return the response.
     * @param request Update operation template request.
     * @return Updated operation template detail response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/template/update", method = RequestMethod.POST)
    public ObjectResponse<OperationTemplateDetailResponse> updateOperationTemplate(@RequestBody ObjectRequest<OperationTemplateUpdateRequest> request) throws Exception {
        return new ObjectResponse<>("OK", powerAuthService.updateOperationTemplate(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeOperationTemplate(OperationTemplateDeleteRequest)} method and
     * return the response.
     * @param request Remove operation template request.
     * @return Simple response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/operation/template/remove", method = RequestMethod.POST)
    public Response removeOperationTemplate(@RequestBody ObjectRequest<OperationTemplateDeleteRequest> request) throws Exception {
        powerAuthService.removeOperationTemplate(request.getRequestObject());
        return new Response();
    }

}
