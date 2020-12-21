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
package io.getlime.security.powerauth.soap.spring.client;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import com.wultra.security.powerauth.client.v3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.SoapFaultDetailElement;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Node;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.dom.DOMSource;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

/**
 * Class implementing a PowerAuth SOAP service client based on provided WSDL
 * service description.
 *
 * The SOAP interface is deprecated. Use the REST interface from module powerauth-rest-client-spring
 * using REST client class PowerAuthRestClient.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@Deprecated
public class PowerAuthServiceClient extends WebServiceGatewaySupport implements PowerAuthClient {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthServiceClient.class);

    /**
     * Call web service endpoint and return a response.
     * @param request Request object.
     * @return Response object.
     * @throws PowerAuthClientException Thrown in case web service call fails.
     */
    private Object callWsApi(Object request) throws PowerAuthClientException {
        try {
            return getWebServiceTemplate().marshalSendAndReceive(request);
        } catch (SoapFaultClientException ex) {
            throw handleSoapError(ex);
        }
    }

    /**
     * Handle SOAP client error and convert it to PowerAuth client exception..
     * @param ex SOAP client error.
     * @return PowerAuth client exception.
     */
    private PowerAuthClientException handleSoapError(SoapFaultClientException ex) {
        SoapFaultDetail faultDetail = ex.getSoapFault().getFaultDetail();
        String errorCode = null;
        String errorMessage = null;
        String localizedErrorMessage = null;
        Integer currentRecoveryPukIndex = null;
        Iterator<SoapFaultDetailElement> iter = faultDetail.getDetailEntries();
        while (iter.hasNext()) {
            SoapFaultDetailElement detail = iter.next();
            Node node = ((DOMSource) detail.getSource()).getNode();
            switch (node.getLocalName()) {
                case "errorCode":
                    errorCode = node.getTextContent();
                    break;
                case "message":
                    errorMessage = node.getTextContent();
                    break;
                case "localizedMessage":
                    localizedErrorMessage = node.getTextContent();
                    break;
                case "currentRecoveryPukIndex":
                    try {
                        currentRecoveryPukIndex = Integer.parseInt(node.getTextContent());
                    } catch (NumberFormatException ex2) {
                        // Ignore invalid index
                    }
                    break;
            }
        }
        // Handle error ERR0028 - Invalid recovery code, other errors are handled as regular activation errors
        PowerAuthError error;
        if ("ERR0028".equals(errorCode)) {
            PowerAuthErrorRecovery errorRecovery = new PowerAuthErrorRecovery();
            if (currentRecoveryPukIndex != null) {
                errorRecovery.setCurrentRecoveryPukIndex(currentRecoveryPukIndex);
            }
            error = errorRecovery;
        } else {
            error = new PowerAuthError();
        }
        error.setCode(errorCode);
        error.setMessage(errorMessage);
        error.setLocalizedMessage(localizedErrorMessage);
        return new PowerAuthClientException(errorMessage, ex, error);
    }

    /**
     * Convert date to XMLGregorianCalendar
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
    public GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws PowerAuthClientException {
        return (GetSystemStatusResponse) callWsApi(request);
    }

    @Override
    public GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException {
        GetSystemStatusRequest request = new GetSystemStatusRequest();
        return (GetSystemStatusResponse) callWsApi(request);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException {
        return (GetErrorCodeListResponse) callWsApi(request);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(String language) throws PowerAuthClientException {
        GetErrorCodeListRequest request = new GetErrorCodeListRequest();
        request.setLanguage(language);
        return (GetErrorCodeListResponse) callWsApi(request);
    }

    @Override
    public InitActivationResponse initActivation(InitActivationRequest request) throws PowerAuthClientException {
        return (InitActivationResponse) callWsApi(request);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId) throws PowerAuthClientException {
        return this.initActivation(userId, applicationId, null, null, ActivationOtpValidation.NONE, null);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId, ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException {
        return this.initActivation(userId, applicationId, null, null, otpValidation, otp);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException {
        return this.initActivation(userId, applicationId, maxFailureCount, timestampActivationExpire, ActivationOtpValidation.NONE, null);
    }

    @Override
    public InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                                 ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException {
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
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException {
        return (PrepareActivationResponse) callWsApi(request);
    }

    @Override
    public PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException {
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
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws PowerAuthClientException {
        return (CreateActivationResponse) callWsApi(request);
    }

    @Override
    public CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                                     String applicationKey, String ephemeralPublicKey, String encryptedData,
                                                     String mac, String nonce) throws PowerAuthClientException {
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
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws PowerAuthClientException {
        return (CommitActivationResponse) callWsApi(request);
    }

    @Override
    public CommitActivationResponse commitActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.commitActivation(request);
    }

    @Override
    public CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return this.commitActivation(request);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException {
        UpdateActivationOtpRequest request = new UpdateActivationOtpRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return updateActivationOtp(request);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException {
        return (UpdateActivationOtpResponse) callWsApi(request);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException {
        return (GetActivationStatusResponse) callWsApi(request);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException {
        GetActivationStatusResponse response = this.getActivationStatusWithEncryptedStatusBlob(activationId, null);
        response.setEncryptedStatusBlob(null);
        return response;
    }

    @Override
    public GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) throws PowerAuthClientException {
        GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        request.setChallenge(challenge);
        return this.getActivationStatus(request);
    }

    @Override
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException {
        return (GetActivationListForUserResponse) callWsApi(request);
    }

    @Override
    public List<GetActivationListForUserResponse.Activations> getActivationListForUser(String userId) throws PowerAuthClientException {
        GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(userId);
        return this.getActivationListForUser(request).getActivations();
    }

    @Override
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws PowerAuthClientException {
        return (LookupActivationsResponse) callWsApi(request);
    }

    @Override
    public List<LookupActivationsResponse.Activations> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws PowerAuthClientException {
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
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws PowerAuthClientException {
        return (UpdateStatusForActivationsResponse) callWsApi(request);
    }

    @Override
    public UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) throws PowerAuthClientException {
        UpdateStatusForActivationsRequest request = new UpdateStatusForActivationsRequest();
        request.getActivationIds().addAll(activationIds);
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        return this.updateStatusForActivations(request);
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException {
        return (RemoveActivationResponse) callWsApi(request);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        return this.removeActivation(activationId, externalUserId, false);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId, Boolean revokeRecoveryCodes) throws PowerAuthClientException {
        RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setRevokeRecoveryCodes(revokeRecoveryCodes);
        return this.removeActivation(request);
    }

    @Override
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws PowerAuthClientException {
        return (BlockActivationResponse) callWsApi(request);
    }

    @Override
    public BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws PowerAuthClientException {
        BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        request.setExternalUserId(externalUserId);
        return this.blockActivation(request);
    }

    @Override
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws PowerAuthClientException {
        return (UnblockActivationResponse) callWsApi(request);
    }

    @Override
    public UnblockActivationResponse unblockActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.unblockActivation(request);
    }

    @Override
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException {
        return (VaultUnlockResponse) callWsApi(request);
    }

    @Override
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                           SignatureType signatureType, String signatureVersion, String signedData,
                                           String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException {
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
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws PowerAuthClientException {
        CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request);
    }

    @Override
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException {
        return (CreatePersonalizedOfflineSignaturePayloadResponse) callWsApi(request);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) throws PowerAuthClientException {
        CreateNonPersonalizedOfflineSignaturePayloadRequest request = new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException {
        return (CreateNonPersonalizedOfflineSignaturePayloadResponse) callWsApi(request);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) throws PowerAuthClientException {
        VerifyOfflineSignatureRequest request = new VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setAllowBiometry(allowBiometry);
        return verifyOfflineSignature(request);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws PowerAuthClientException {
        return (VerifyOfflineSignatureResponse) callWsApi(request);
    }

    @Override
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws PowerAuthClientException {
        return (VerifySignatureResponse) callWsApi(request);
    }

    @Override
    public VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) throws PowerAuthClientException {
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
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws PowerAuthClientException {
        return (VerifyECDSASignatureResponse) callWsApi(request);
    }

    @Override
    public VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws PowerAuthClientException {
        VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    @Override
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException {
        return (SignatureAuditResponse) callWsApi(request);
    }

    @Override
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    @Override
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    @Override
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws PowerAuthClientException {
        return (ActivationHistoryResponse) callWsApi(request);
    }

    @Override
    public List<ActivationHistoryResponse.Items> getActivationHistory(String activationId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        ActivationHistoryRequest request = new ActivationHistoryRequest();
        request.setActivationId(activationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getActivationHistory(request).getItems();
    }

    @Override
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws PowerAuthClientException {
        return (GetApplicationListResponse) callWsApi(request);
    }

    @Override
    public List<GetApplicationListResponse.Applications> getApplicationList() throws PowerAuthClientException {
        return this.getApplicationList(new GetApplicationListRequest()).getApplications();
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException {
        return (GetApplicationDetailResponse) callWsApi(request);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws PowerAuthClientException {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(String applicationName) throws PowerAuthClientException {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(applicationName);
        return this.getApplicationDetail(request);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws PowerAuthClientException {
        return (LookupApplicationByAppKeyResponse) callWsApi(request);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) throws PowerAuthClientException {
        LookupApplicationByAppKeyRequest request = new LookupApplicationByAppKeyRequest();
        request.setApplicationKey(applicationKey);
        return this.lookupApplicationByAppKey(request);
    }

    @Override
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws PowerAuthClientException {
        return (CreateApplicationResponse) callWsApi(request);
    }

    @Override
    public CreateApplicationResponse createApplication(String name) throws PowerAuthClientException {
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws PowerAuthClientException {
        return (CreateApplicationVersionResponse) callWsApi(request);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws PowerAuthClientException {
        CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws PowerAuthClientException {
        return (UnsupportApplicationVersionResponse) callWsApi(request);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws PowerAuthClientException {
        UnsupportApplicationVersionRequest request = new UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws PowerAuthClientException {
        return (SupportApplicationVersionResponse) callWsApi(request);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws PowerAuthClientException {
        SupportApplicationVersionRequest request = new SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    @Override
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws PowerAuthClientException {
        return (CreateIntegrationResponse) callWsApi(request);
    }

    @Override
    public CreateIntegrationResponse createIntegration(String name) throws PowerAuthClientException {
        CreateIntegrationRequest request = new CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    @Override
    public GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws PowerAuthClientException {
        return (GetIntegrationListResponse) callWsApi(request);
    }

    @Override
    public List<GetIntegrationListResponse.Items> getIntegrationList() throws PowerAuthClientException {
        return this.getIntegrationList(new GetIntegrationListRequest()).getItems();
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws PowerAuthClientException {
        return (RemoveIntegrationResponse) callWsApi(request);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(String id) throws PowerAuthClientException {
        RemoveIntegrationRequest request = new RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws PowerAuthClientException {
        return (CreateCallbackUrlResponse) callWsApi(request);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl, List<String> attributes) throws PowerAuthClientException {
        CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        return this.createCallbackUrl(request);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException {
        return (UpdateCallbackUrlResponse) callWsApi(request);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(String id, long applicationId, String name, String callbackUrl, List<String> attributes) throws PowerAuthClientException {
        UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setId(id);
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        return this.updateCallbackUrl(request);
    }

    @Override
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws PowerAuthClientException {
        return (GetCallbackUrlListResponse) callWsApi(request);
    }

    @Override
    public List<GetCallbackUrlListResponse.CallbackUrlList> getCallbackUrlList(Long applicationId) throws PowerAuthClientException {
        GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return getCallbackUrlList(request).getCallbackUrlList();
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws PowerAuthClientException {
        return (RemoveCallbackUrlResponse) callWsApi(request);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws PowerAuthClientException {
        RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }

    @Override
    public CreateTokenResponse createToken(CreateTokenRequest request) throws PowerAuthClientException {
        return (CreateTokenResponse) callWsApi(request);
    }

    @Override
    public CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                           String encryptedData, String mac, String nonce, SignatureType signatureType) throws PowerAuthClientException {
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
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws PowerAuthClientException {
        return (ValidateTokenResponse) callWsApi(request);
    }

    @Override
    public ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws PowerAuthClientException {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setTokenDigest(tokenDigest);
        return validateToken(request);
    }

    @Override
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) throws PowerAuthClientException {
        return (RemoveTokenResponse) callWsApi(request);
    }

    @Override
    public RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException {
        RemoveTokenRequest request = new RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws PowerAuthClientException {
        return (GetEciesDecryptorResponse) callWsApi(request);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthClientException {
        GetEciesDecryptorRequest request = new GetEciesDecryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        return getEciesDecryptor(request);
    }

    @Override
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws PowerAuthClientException {
        return (StartUpgradeResponse) callWsApi(request);
    }

    @Override
    public StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                                 String encryptedData, String mac, String nonce) throws PowerAuthClientException {
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
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws PowerAuthClientException {
        return (CommitUpgradeResponse) callWsApi(request);
    }

    @Override
    public CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) throws PowerAuthClientException {
        CommitUpgradeRequest request = new CommitUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        return commitUpgrade(request);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws PowerAuthClientException {
        return (CreateRecoveryCodeResponse) callWsApi(request);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount) throws PowerAuthClientException {
        CreateRecoveryCodeRequest request = new CreateRecoveryCodeRequest();
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setPukCount(pukCount);
        return createRecoveryCode(request);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws PowerAuthClientException {
        return (ConfirmRecoveryCodeResponse) callWsApi(request);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                           String encryptedData, String mac, String nonce) throws PowerAuthClientException {
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
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws PowerAuthClientException {
        return (LookupRecoveryCodesResponse) callWsApi(request);
    }

    @Override
    public LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                           RecoveryCodeStatus recoveryCodeStatus, RecoveryPukStatus recoveryPukStatus) throws PowerAuthClientException {
        LookupRecoveryCodesRequest request = new LookupRecoveryCodesRequest();
        request.setUserId(userId);
        request.setActivationId(activationId);
        request.setApplicationId(applicationId);
        request.setRecoveryCodeStatus(recoveryCodeStatus);
        request.setRecoveryPukStatus(recoveryPukStatus);
        return lookupRecoveryCodes(request);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws PowerAuthClientException {
        return (RevokeRecoveryCodesResponse) callWsApi(request);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) throws PowerAuthClientException {
        RevokeRecoveryCodesRequest request = new RevokeRecoveryCodesRequest();
        request.getRecoveryCodeIds().addAll(recoveryCodeIds);
        return revokeRecoveryCodes(request);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws PowerAuthClientException {
        return (RecoveryCodeActivationResponse) callWsApi(request);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                            String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException {
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
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws PowerAuthClientException {
        return (GetRecoveryConfigResponse) callWsApi(request);
    }

    @Override
    public GetRecoveryConfigResponse getRecoveryConfig(Long applicationId) throws PowerAuthClientException {
        GetRecoveryConfigRequest request = new GetRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        return getRecoveryConfig(request);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws PowerAuthClientException {
        return (UpdateRecoveryConfigResponse) callWsApi(request);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) throws PowerAuthClientException {
        UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        request.setActivationRecoveryEnabled(activationRecoveryEnabled);
        request.setRecoveryPostcardEnabled(recoveryPostcardEnabled);
        request.setAllowMultipleRecoveryCodes(allowMultipleRecoveryCodes);
        request.setRemotePostcardPublicKey(remoteRecoveryPublicKeyBase64);
        return updateRecoveryConfig(request);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws PowerAuthClientException {
        return (ListActivationFlagsResponse) callWsApi(request);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(String activationId) throws PowerAuthClientException {
        ListActivationFlagsRequest request = new ListActivationFlagsRequest();
        request.setActivationId(activationId);
        return listActivationFlags(request);
    }

    @Override
    public AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) {
        return (AddActivationFlagsResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    @Override
    public AddActivationFlagsResponse addActivationFlags(String activationId, List<String> activationFlags) {
        AddActivationFlagsRequest request = new AddActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return addActivationFlags(request);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws PowerAuthClientException {
        return (UpdateActivationFlagsResponse) callWsApi(request);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        UpdateActivationFlagsRequest request = new UpdateActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return updateActivationFlags(request);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws PowerAuthClientException {
        return (RemoveActivationFlagsResponse) callWsApi(request);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        RemoveActivationFlagsRequest request = new RemoveActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return removeActivationFlags(request);
    }

    @Override
    public ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) {
        return (ListApplicationRolesResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    @Override
    public ListApplicationRolesResponse listApplicationRoles(Long applicationId) {
        ListApplicationRolesRequest request = new ListApplicationRolesRequest();
        request.setApplicationId(applicationId);
        return listApplicationRoles(request);
    }

    @Override
    public AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) {
        return (AddApplicationRolesResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    @Override
    public AddApplicationRolesResponse addApplicationRoles(Long applicationId, List<String> applicationRoles) {
        AddApplicationRolesRequest request = new AddApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return addApplicationRoles(request);
    }

    @Override
    public UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) {
        return (UpdateApplicationRolesResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    @Override
    public UpdateApplicationRolesResponse updateApplicationRoles(Long applicationId, List<String> applicationRoles) {
        UpdateApplicationRolesRequest request = new UpdateApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return updateApplicationRoles(request);
    }

    @Override
    public RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) {
        return (RemoveApplicationRolesResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    @Override
    public RemoveApplicationRolesResponse removeApplicationRoles(Long applicationId, List<String> applicationRoles) {
        RemoveApplicationRolesRequest request = new RemoveApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return removeApplicationRoles(request);
    }

    @Override
    public OperationDetailResponse createOperation(OperationCreateRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OperationDetailResponse operationDetail(OperationDetailRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OperationListResponse operationList(OperationListForUserRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OperationListResponse operationPendingList(OperationListForUserRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OperationDetailResponse operationCancel(OperationCancelRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OperationUserActionResponse operationApprove(OperationApproveRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OperationUserActionResponse operationReject(OperationRejectRequest request) throws PowerAuthClientException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Get the PowerAuth 2.0 client. This client will be deprecated in future release.
     * @return PowerAuth 2.0 client.
     */
    public PowerAuthServiceClientV2 v2() {
        return new PowerAuthServiceClientV2();
    }

    /**
     * Client with PowerAuth version 2.0 methods. This client will be deprecated in future release.
     */
    public class PowerAuthServiceClientV2 implements PowerAuthClient.PowerAuthClientV2 {

        @Override
        public com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(com.wultra.security.powerauth.client.v2.PrepareActivationRequest request) throws PowerAuthClientException {
            return (com.wultra.security.powerauth.client.v2.PrepareActivationResponse) callWsApi(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) throws PowerAuthClientException {
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
        public com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(com.wultra.security.powerauth.client.v2.CreateActivationRequest request) throws PowerAuthClientException {
            return (com.wultra.security.powerauth.client.v2.CreateActivationResponse) callWsApi(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws PowerAuthClientException {
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
        public com.wultra.security.powerauth.client.v2.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws PowerAuthClientException {
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
        public com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(com.wultra.security.powerauth.client.v2.VaultUnlockRequest request) throws PowerAuthClientException {
            return (com.wultra.security.powerauth.client.v2.VaultUnlockResponse) callWsApi(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, com.wultra.security.powerauth.client.v2.SignatureType signatureType, String reason) throws PowerAuthClientException {
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
        public com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest request) throws PowerAuthClientException {
            return (com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse) callWsApi(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) throws PowerAuthClientException {
            com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest request = new com.wultra.security.powerauth.client.v2.GetPersonalizedEncryptionKeyRequest();
            request.setActivationId(activationId);
            request.setSessionIndex(sessionIndex);
            return this.generatePersonalizedE2EEncryptionKey(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest request) throws PowerAuthClientException {
            return (com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse) callWsApi(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) throws PowerAuthClientException {
            com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest request = new com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyRequest();
            request.setApplicationKey(applicationKey);
            request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
            request.setSessionIndex(sessionIndex);
            return this.generateNonPersonalizedE2EEncryptionKey(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(com.wultra.security.powerauth.client.v2.CreateTokenRequest request) throws PowerAuthClientException {
            return (com.wultra.security.powerauth.client.v2.CreateTokenResponse) callWsApi(request);
        }

        @Override
        public com.wultra.security.powerauth.client.v2.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, com.wultra.security.powerauth.client.v2.SignatureType signatureType) throws PowerAuthClientException {
            com.wultra.security.powerauth.client.v2.CreateTokenRequest request = new com.wultra.security.powerauth.client.v2.CreateTokenRequest();
            request.setActivationId(activationId);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setSignatureType(signatureType);
            return createToken(request);
        }

    }

}
