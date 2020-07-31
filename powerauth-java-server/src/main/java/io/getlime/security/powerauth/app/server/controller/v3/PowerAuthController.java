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

import com.wultra.security.powerauth.client.model.PowerAuthRequestWrapper;
import com.wultra.security.powerauth.client.model.PowerAuthResponseWrapper;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
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
    public PowerAuthResponseWrapper<GetSystemStatusResponse> getSystemStatus(@RequestBody PowerAuthRequestWrapper<GetSystemStatusRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getSystemStatus(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetErrorCodeListResponse> getErrorCodeList(@RequestBody PowerAuthRequestWrapper<GetErrorCodeListRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getErrorCodeList(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<InitActivationResponse> initActivation(@RequestBody PowerAuthRequestWrapper<InitActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.initActivation(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<PrepareActivationResponse> prepareActivation(@RequestBody PowerAuthRequestWrapper<PrepareActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.prepareActivation(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateActivationResponse> createActivation(@RequestBody PowerAuthRequestWrapper<CreateActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateActivationOtp(UpdateActivationOtpRequest)} method and return the response.
     * @param request Update activation OTP request.
     * @return Update activation OTP response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/otp/update", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<UpdateActivationOtpResponse> updateActivationOtp(@RequestBody PowerAuthRequestWrapper<UpdateActivationOtpRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.updateActivationOtp(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CommitActivationResponse> commitActivation(@RequestBody PowerAuthRequestWrapper<CommitActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.commitActivation(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetActivationStatusResponse> getActivationStatus(@RequestBody PowerAuthRequestWrapper<GetActivationStatusRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getActivationStatus(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<RemoveActivationResponse> removeActivation(@RequestBody PowerAuthRequestWrapper<RemoveActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.removeActivation(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetActivationListForUserResponse> getActivationListForUser(@RequestBody PowerAuthRequestWrapper<GetActivationListForUserRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getActivationListForUser(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<LookupActivationsResponse> lookupActivations(@RequestBody PowerAuthRequestWrapper<LookupActivationsRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.lookupActivations(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<UpdateStatusForActivationsResponse> updateStatusForActivations(@RequestBody PowerAuthRequestWrapper<UpdateStatusForActivationsRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.updateStatusForActivations(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<VerifySignatureResponse> verifySignature(@RequestBody PowerAuthRequestWrapper<VerifySignatureRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.verifySignature(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreatePersonalizedOfflineSignaturePayloadResponse> createPersonalizedOfflineSignaturePayload(@RequestBody PowerAuthRequestWrapper<CreatePersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createPersonalizedOfflineSignaturePayload(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateNonPersonalizedOfflineSignaturePayloadResponse> createNonPersonalizedOfflineSignaturePayload(@RequestBody PowerAuthRequestWrapper<CreateNonPersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createNonPersonalizedOfflineSignaturePayload(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<VerifyOfflineSignatureResponse> verifyOfflineSignature(@RequestBody PowerAuthRequestWrapper<VerifyOfflineSignatureRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.verifyOfflineSignature(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<VaultUnlockResponse> vaultUnlock(@RequestBody PowerAuthRequestWrapper<VaultUnlockRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.vaultUnlock(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<VerifyECDSASignatureResponse> verifyECDSASignature(@RequestBody PowerAuthRequestWrapper<VerifyECDSASignatureRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.verifyECDSASignature(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<SignatureAuditResponse> getSignatureAuditLog(@RequestBody PowerAuthRequestWrapper<SignatureAuditRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getSignatureAuditLog(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<ActivationHistoryResponse> getActivationHistory(@RequestBody PowerAuthRequestWrapper<ActivationHistoryRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getActivationHistory(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<BlockActivationResponse> blockActivation(@RequestBody PowerAuthRequestWrapper<BlockActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.blockActivation(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<UnblockActivationResponse> unblockActivation(@RequestBody PowerAuthRequestWrapper<UnblockActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.unblockActivation(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetApplicationListResponse> getApplicationList(@RequestBody PowerAuthRequestWrapper<GetApplicationListRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getApplicationList(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetApplicationDetailResponse> getApplicationDetail(@RequestBody PowerAuthRequestWrapper<GetApplicationDetailRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getApplicationDetail(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<LookupApplicationByAppKeyResponse> lookupApplicationByAppKey(@RequestBody PowerAuthRequestWrapper<LookupApplicationByAppKeyRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.lookupApplicationByAppKey(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateApplicationResponse> createApplication(@RequestBody PowerAuthRequestWrapper<CreateApplicationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createApplication(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateApplicationVersionResponse> createApplicationVersion(@RequestBody PowerAuthRequestWrapper<CreateApplicationVersionRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createApplicationVersion(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<UnsupportApplicationVersionResponse> unsupportApplicationVersion(@RequestBody PowerAuthRequestWrapper<UnsupportApplicationVersionRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.unsupportApplicationVersion(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<SupportApplicationVersionResponse> supportApplicationVersion(@RequestBody PowerAuthRequestWrapper<SupportApplicationVersionRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.supportApplicationVersion(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateIntegrationResponse> createIntegration(@RequestBody PowerAuthRequestWrapper<CreateIntegrationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createIntegration(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getIntegrationList()} method and
     * return the response.
     *
     * @return Get integration list response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/integration/list", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<GetIntegrationListResponse> getIntegrationList() throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getIntegrationList());
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
    public PowerAuthResponseWrapper<RemoveIntegrationResponse> removeIntegration(@RequestBody PowerAuthRequestWrapper<RemoveIntegrationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.removeIntegration(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateCallbackUrlResponse> createCallbackUrl(@RequestBody PowerAuthRequestWrapper<CreateCallbackUrlRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createCallbackUrl(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<UpdateCallbackUrlResponse> updateCallbackUrl(@RequestBody PowerAuthRequestWrapper<UpdateCallbackUrlRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.updateCallbackUrl(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetCallbackUrlListResponse> getCallbackUrlList(@RequestBody PowerAuthRequestWrapper<GetCallbackUrlListRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getCallbackUrlList(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<RemoveCallbackUrlResponse> removeCallbackUrl(@RequestBody PowerAuthRequestWrapper<RemoveCallbackUrlRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.removeCallbackUrl(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<CreateTokenResponse> createToken(@RequestBody PowerAuthRequestWrapper<CreateTokenRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createToken(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<ValidateTokenResponse> validateToken(@RequestBody PowerAuthRequestWrapper<ValidateTokenRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.validateToken(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<RemoveTokenResponse> removeToken(@RequestBody PowerAuthRequestWrapper<RemoveTokenRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.removeToken(request.getRequestObject()));
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
    public PowerAuthResponseWrapper<GetEciesDecryptorResponse> getEciesDecryptor(@RequestBody PowerAuthRequestWrapper<GetEciesDecryptorRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getEciesDecryptor(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#startUpgrade(StartUpgradeRequest)} method and
     * return the response.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/upgrade/start", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<StartUpgradeResponse> startUpgrade(@RequestBody PowerAuthRequestWrapper<StartUpgradeRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.startUpgrade(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#commitUpgrade(CommitUpgradeRequest)} method and
     * return the response.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/upgrade/commit", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<CommitUpgradeResponse> commitUpgrade(@RequestBody PowerAuthRequestWrapper<CommitUpgradeRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.commitUpgrade(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createRecoveryCode(CreateRecoveryCodeRequest)} method and
     * return the response.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/create", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<CreateRecoveryCodeResponse> createRecoveryCodeForUser(@RequestBody PowerAuthRequestWrapper<CreateRecoveryCodeRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#confirmRecoveryCode(ConfirmRecoveryCodeRequest)} method and
     * return the response.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/confirm", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<ConfirmRecoveryCodeResponse> confirmRecoveryCode(@RequestBody PowerAuthRequestWrapper<ConfirmRecoveryCodeRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.confirmRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#lookupRecoveryCodes(LookupRecoveryCodesRequest)} method and
     * return the response.
     * @param request Lookup recovery codes request.
     * @return Lookup recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/lookup", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<LookupRecoveryCodesResponse> lookupRecoveryCodesRequest(@RequestBody PowerAuthRequestWrapper<LookupRecoveryCodesRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.lookupRecoveryCodes(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#revokeRecoveryCodes(RevokeRecoveryCodesRequest)} method and
     * return the response.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/revoke", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<RevokeRecoveryCodesResponse> revokeRecoveryCodesRequest(@RequestBody PowerAuthRequestWrapper<RevokeRecoveryCodesRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.revokeRecoveryCodes(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createActivationUsingRecoveryCode(RecoveryCodeActivationRequest)} method and
     * return the response.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/recovery/create", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<RecoveryCodeActivationResponse> createActivationUsingRecoveryCode(@RequestBody PowerAuthRequestWrapper<RecoveryCodeActivationRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.createActivationUsingRecoveryCode(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#getRecoveryConfig(GetRecoveryConfigRequest)} method and
     * return the response.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/config/detail", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<GetRecoveryConfigResponse> getRecoveryConfig(@RequestBody PowerAuthRequestWrapper<GetRecoveryConfigRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.getRecoveryConfig(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateRecoveryConfig(UpdateRecoveryConfigRequest)} method and
     * return the response.
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/recovery/config/update", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<UpdateRecoveryConfigResponse> updateRecoveryConfig(@RequestBody PowerAuthRequestWrapper<UpdateRecoveryConfigRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.updateRecoveryConfig(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#listActivationFlags(ListActivationFlagsRequest)} method and
     * return the response.
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/list", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<ListActivationFlagsResponse> listActivationFlags(@RequestBody PowerAuthRequestWrapper<ListActivationFlagsRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.listActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#addActivationFlags(AddActivationFlagsRequest)} method and
     * return the response.
     * @param request Add activation flags request.
     * @return Add activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/create", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<AddActivationFlagsResponse> addActivationFlags(@RequestBody PowerAuthRequestWrapper<AddActivationFlagsRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.addActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateActivationFlags(UpdateActivationFlagsRequest)} method and
     * return the response.
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/update", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<UpdateActivationFlagsResponse> updateActivationFlags(@RequestBody PowerAuthRequestWrapper<UpdateActivationFlagsRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.updateActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeActivationFlags(RemoveActivationFlagsRequest)} method and
     * return the response.
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/flags/remove", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<RemoveActivationFlagsResponse> removeActivationFlags(@RequestBody PowerAuthRequestWrapper<RemoveActivationFlagsRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.removeActivationFlags(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#listApplicationRoles(ListApplicationRolesRequest)} method and
     * return the response.
     * @param request List application roles request.
     * @return List application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/list", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<ListApplicationRolesResponse> listApplicationRoles(@RequestBody PowerAuthRequestWrapper<ListApplicationRolesRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.listApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#addApplicationRoles(AddApplicationRolesRequest)} method and
     * return the response.
     * @param request Create application roles request.
     * @return Create application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/create", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<AddApplicationRolesResponse> addApplicationRoles(@RequestBody PowerAuthRequestWrapper<AddApplicationRolesRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.addApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#updateApplicationRoles(UpdateApplicationRolesRequest)} method and
     * return the response.
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/update", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<UpdateApplicationRolesResponse> updateApplicationRoles(@RequestBody PowerAuthRequestWrapper<UpdateApplicationRolesRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.updateApplicationRoles(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#removeApplicationRoles(RemoveApplicationRolesRequest)} method and
     * return the response.
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/roles/remove", method = RequestMethod.POST)
    public PowerAuthResponseWrapper<RemoveApplicationRolesResponse> removeApplicationRoles(@RequestBody PowerAuthRequestWrapper<RemoveApplicationRolesRequest> request) throws Exception {
        return new PowerAuthResponseWrapper<>("OK", powerAuthService.removeApplicationRoles(request.getRequestObject()));
    }


}
