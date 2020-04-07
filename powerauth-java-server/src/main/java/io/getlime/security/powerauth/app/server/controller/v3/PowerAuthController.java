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

import io.getlime.security.powerauth.app.server.controller.RESTRequestWrapper;
import io.getlime.security.powerauth.app.server.controller.RESTResponseWrapper;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
import io.getlime.security.powerauth.v3.*;
import io.swagger.annotations.Api;
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
@Api(tags={"PowerAuth Controller V3"})
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
    public RESTResponseWrapper<GetSystemStatusResponse> getSystemStatus(@RequestBody RESTRequestWrapper<GetSystemStatusRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getSystemStatus(request.getRequestObject()));
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
    public RESTResponseWrapper<GetErrorCodeListResponse> getErrorCodeList(@RequestBody RESTRequestWrapper<GetErrorCodeListRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getErrorCodeList(request.getRequestObject()));
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
    public RESTResponseWrapper<InitActivationResponse> initActivation(@RequestBody RESTRequestWrapper<InitActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.initActivation(request.getRequestObject()));
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
    public RESTResponseWrapper<PrepareActivationResponse> prepareActivation(@RequestBody RESTRequestWrapper<PrepareActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.prepareActivation(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateActivationResponse> createActivation(@RequestBody RESTRequestWrapper<CreateActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateActivationOtp(UpdateActivationOtpRequest)} method and return the response.
     * @param request Update activation OTP request.
     * @return Update activation OTP response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/otp/update", method = RequestMethod.POST)
    public RESTResponseWrapper<UpdateActivationOtpResponse> updateActivationOtp(@RequestBody RESTRequestWrapper<UpdateActivationOtpRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.updateActivationOtp(request.getRequestObject()));
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
    public RESTResponseWrapper<CommitActivationResponse> commitActivation(@RequestBody RESTRequestWrapper<CommitActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.commitActivation(request.getRequestObject()));
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
    public RESTResponseWrapper<GetActivationStatusResponse> getActivationStatus(@RequestBody RESTRequestWrapper<GetActivationStatusRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getActivationStatus(request.getRequestObject()));
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
    public RESTResponseWrapper<RemoveActivationResponse> removeActivation(@RequestBody RESTRequestWrapper<RemoveActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.removeActivation(request.getRequestObject()));
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
    public RESTResponseWrapper<GetActivationListForUserResponse> getActivationListForUser(@RequestBody RESTRequestWrapper<GetActivationListForUserRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getActivationListForUser(request.getRequestObject()));
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
    public RESTResponseWrapper<LookupActivationsResponse> lookupActivations(@RequestBody RESTRequestWrapper<LookupActivationsRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.lookupActivations(request.getRequestObject()));
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
    public RESTResponseWrapper<UpdateStatusForActivationsResponse> updateStatusForActivations(@RequestBody RESTRequestWrapper<UpdateStatusForActivationsRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.updateStatusForActivations(request.getRequestObject()));
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
    public RESTResponseWrapper<VerifySignatureResponse> verifySignature(@RequestBody RESTRequestWrapper<VerifySignatureRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.verifySignature(request.getRequestObject()));
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
    public RESTResponseWrapper<CreatePersonalizedOfflineSignaturePayloadResponse> createPersonalizedOfflineSignaturePayload(@RequestBody RESTRequestWrapper<CreatePersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createPersonalizedOfflineSignaturePayload(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateNonPersonalizedOfflineSignaturePayloadResponse> createNonPersonalizedOfflineSignaturePayload(@RequestBody RESTRequestWrapper<CreateNonPersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createNonPersonalizedOfflineSignaturePayload(request.getRequestObject()));
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
    public RESTResponseWrapper<VerifyOfflineSignatureResponse> verifyOfflineSignature(@RequestBody RESTRequestWrapper<VerifyOfflineSignatureRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.verifyOfflineSignature(request.getRequestObject()));
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
    public RESTResponseWrapper<VaultUnlockResponse> vaultUnlock(@RequestBody RESTRequestWrapper<VaultUnlockRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.vaultUnlock(request.getRequestObject()));
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
    public RESTResponseWrapper<VerifyECDSASignatureResponse> verifyECDSASignature(@RequestBody RESTRequestWrapper<VerifyECDSASignatureRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.verifyECDSASignature(request.getRequestObject()));
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
    public RESTResponseWrapper<SignatureAuditResponse> getSignatureAuditLog(@RequestBody RESTRequestWrapper<SignatureAuditRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getSignatureAuditLog(request.getRequestObject()));
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
    public RESTResponseWrapper<ActivationHistoryResponse> getActivationHistory(@RequestBody RESTRequestWrapper<ActivationHistoryRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getActivationHistory(request.getRequestObject()));
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
    public RESTResponseWrapper<BlockActivationResponse> blockActivation(@RequestBody RESTRequestWrapper<BlockActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.blockActivation(request.getRequestObject()));
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
    public RESTResponseWrapper<UnblockActivationResponse> unblockActivation(@RequestBody RESTRequestWrapper<UnblockActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.unblockActivation(request.getRequestObject()));
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
    public RESTResponseWrapper<GetApplicationListResponse> getApplicationList(@RequestBody RESTRequestWrapper<GetApplicationListRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getApplicationList(request.getRequestObject()));
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
    public RESTResponseWrapper<GetApplicationDetailResponse> getApplicationDetail(@RequestBody RESTRequestWrapper<GetApplicationDetailRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getApplicationDetail(request.getRequestObject()));
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
    public RESTResponseWrapper<LookupApplicationByAppKeyResponse> lookupApplicationByAppKey(@RequestBody RESTRequestWrapper<LookupApplicationByAppKeyRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.lookupApplicationByAppKey(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateApplicationResponse> createApplication(@RequestBody RESTRequestWrapper<CreateApplicationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createApplication(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateApplicationVersionResponse> createApplicationVersion(@RequestBody RESTRequestWrapper<CreateApplicationVersionRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createApplicationVersion(request.getRequestObject()));
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
    public RESTResponseWrapper<UnsupportApplicationVersionResponse> unsupportApplicationVersion(@RequestBody RESTRequestWrapper<UnsupportApplicationVersionRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.unsupportApplicationVersion(request.getRequestObject()));
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
    public RESTResponseWrapper<SupportApplicationVersionResponse> supportApplicationVersion(@RequestBody RESTRequestWrapper<SupportApplicationVersionRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.supportApplicationVersion(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateIntegrationResponse> createIntegration(@RequestBody RESTRequestWrapper<CreateIntegrationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createIntegration(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getIntegrationList()} method and
     * return the response.
     *
     * @return Get integration list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/integration/list", method = RequestMethod.POST)
    public RESTResponseWrapper<GetIntegrationListResponse> getIntegrationList() throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getIntegrationList());
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
    public RESTResponseWrapper<RemoveIntegrationResponse> removeIntegration(@RequestBody RESTRequestWrapper<RemoveIntegrationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.removeIntegration(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateCallbackUrlResponse> createCallbackUrl(@RequestBody RESTRequestWrapper<CreateCallbackUrlRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createCallbackUrl(request.getRequestObject()));
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
    public RESTResponseWrapper<GetCallbackUrlListResponse> getCallbackUrlList(@RequestBody RESTRequestWrapper<GetCallbackUrlListRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getCallbackUrlList(request.getRequestObject()));
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
    public RESTResponseWrapper<RemoveCallbackUrlResponse> removeCallbackUrl(@RequestBody RESTRequestWrapper<RemoveCallbackUrlRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.removeCallbackUrl(request.getRequestObject()));
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
    public RESTResponseWrapper<CreateTokenResponse> createToken(@RequestBody RESTRequestWrapper<CreateTokenRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createToken(request.getRequestObject()));
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
    public RESTResponseWrapper<ValidateTokenResponse> validateToken(@RequestBody RESTRequestWrapper<ValidateTokenRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.validateToken(request.getRequestObject()));
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
    public RESTResponseWrapper<RemoveTokenResponse> removeToken(@RequestBody RESTRequestWrapper<RemoveTokenRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.removeToken(request.getRequestObject()));
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
    public RESTResponseWrapper<GetEciesDecryptorResponse> getEciesDecryptor(@RequestBody RESTRequestWrapper<GetEciesDecryptorRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getEciesDecryptor(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#startUpgrade(StartUpgradeRequest)} method and
     * return the response.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/upgrade/start", method = RequestMethod.POST)
    public RESTResponseWrapper<StartUpgradeResponse> startUpgrade(@RequestBody RESTRequestWrapper<StartUpgradeRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.startUpgrade(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#commitUpgrade(CommitUpgradeRequest)} method and
     * return the response.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/upgrade/commit", method = RequestMethod.POST)
    public RESTResponseWrapper<CommitUpgradeResponse> commitUpgrade(@RequestBody RESTRequestWrapper<CommitUpgradeRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.commitUpgrade(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createRecoveryCode(CreateRecoveryCodeRequest)} method and
     * return the response.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/create", method = RequestMethod.POST)
    public RESTResponseWrapper<CreateRecoveryCodeResponse> createRecoveryCodeForUser(@RequestBody RESTRequestWrapper<CreateRecoveryCodeRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#confirmRecoveryCode(ConfirmRecoveryCodeRequest)} method and
     * return the response.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/confirm", method = RequestMethod.POST)
    public RESTResponseWrapper<ConfirmRecoveryCodeResponse> confirmRecoveryCode(@RequestBody RESTRequestWrapper<ConfirmRecoveryCodeRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.confirmRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#lookupRecoveryCodes(LookupRecoveryCodesRequest)} method and
     * return the response.
     * @param request Lookup recovery codes request.
     * @return Lookup recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/lookup", method = RequestMethod.POST)
    public RESTResponseWrapper<LookupRecoveryCodesResponse> lookupRecoveryCodesRequest(@RequestBody RESTRequestWrapper<LookupRecoveryCodesRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.lookupRecoveryCodes(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#revokeRecoveryCodes(RevokeRecoveryCodesRequest)} method and
     * return the response.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/revoke", method = RequestMethod.POST)
    public RESTResponseWrapper<RevokeRecoveryCodesResponse> revokeRecoveryCodesRequest(@RequestBody RESTRequestWrapper<RevokeRecoveryCodesRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.revokeRecoveryCodes(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createActivationUsingRecoveryCode(RecoveryCodeActivationRequest)} method and
     * return the response.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/recovery/create", method = RequestMethod.POST)
    public RESTResponseWrapper<RecoveryCodeActivationResponse> createActivationUsingRecoveryCode(@RequestBody RESTRequestWrapper<RecoveryCodeActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createActivationUsingRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getRecoveryConfig(GetRecoveryConfigRequest)} method and
     * return the response.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/config/detail", method = RequestMethod.POST)
    public RESTResponseWrapper<GetRecoveryConfigResponse> getRecoveryConfig(@RequestBody RESTRequestWrapper<GetRecoveryConfigRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getRecoveryConfig(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateRecoveryConfig(UpdateRecoveryConfigRequest)} method and
     * return the response.
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/config/update", method = RequestMethod.POST)
    public RESTResponseWrapper<UpdateRecoveryConfigResponse> updateRecoveryConfig(@RequestBody RESTRequestWrapper<UpdateRecoveryConfigRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.updateRecoveryConfig(request.getRequestObject()));
    }

}
