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

import io.getlime.powerauth.soap.v3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Class implementing a PowerAuth SOAP service client based on provided WSDL
 * service description.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthServiceClient extends WebServiceGatewaySupport {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthServiceClient.class);

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

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link GetSystemStatusRequest} instance
     * @return {@link GetSystemStatusResponse}
     */
    public GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) {
        return (GetSystemStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @return {@link GetSystemStatusResponse}
     */
    public GetSystemStatusResponse getSystemStatus() {
        GetSystemStatusRequest request = new GetSystemStatusRequest();
        return (GetSystemStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link InitActivationRequest} instance
     * @return {@link InitActivationResponse}
     */
    public InitActivationResponse initActivation(InitActivationRequest request) {
        return (InitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link InitActivationResponse}
     */
    public InitActivationResponse initActivation(String userId, Long applicationId) {
        return this.initActivation(userId, applicationId, null, null);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link InitActivationResponse}
     */
    public InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) {
        InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(calendarWithDate(timestampActivationExpire));
        }
        return this.initActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link PrepareActivationRequest} instance
     * @return {@link PrepareActivationResponse}
     */
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
        return (PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationCode Activation code.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac Mac of key and data for ECIES.
     * @param nonce Nonce for ECIES.
     * @return {@link PrepareActivationResponse}
     */
    public PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce) {
        PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return prepareActivation(request);
    }

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth Server
     * SOAP interface.
     * @param request Create activation request.
     * @return Create activation response.
     */
    public CreateActivationResponse createActivation(CreateActivationRequest request) {
        return (CreateActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the createActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID.
     * @param timestampActivationExpire Expiration timestamp for activation (optional).
     * @param maxFailureCount Maximum failure count (optional).
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac Mac of key and data for ECIES.
     * @param nonce Nonce for ECIES.
     * @return {@link CreateActivationResponse}
     */
    public CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                                     String applicationKey, String ephemeralPublicKey, String encryptedData,
                                                     String mac, String nonce) {
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

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link CommitActivationRequest} instance
     * @return {@link CommitActivationResponse}
     */
    public CommitActivationResponse commitActivation(CommitActivationRequest request) {
        return (CommitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID for activation to be commited.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @return {@link CommitActivationResponse}
     */
    public CommitActivationResponse commitActivation(String activationId, String externalUserId) {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.commitActivation(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link GetActivationStatusRequest} instance
     * @return {@link GetActivationStatusResponse}
     */
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) {
        return (GetActivationStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface. This method should be used only
     * to acquire the activation status for other, than PowerAuth standard RESTful API purposes. If you're implementing
     * the PowerAuth standard RESTful API, then use {@link #getActivationStatusWithEncryptedStatusBlob(String, String)}
     * method instead.
     *
     * @param activationId Activation Id to lookup information for.
     * @return {@link GetActivationStatusResponse}
     */
    public GetActivationStatusResponse getActivationStatus(String activationId) {
        GetActivationStatusResponse response = this.getActivationStatusWithEncryptedStatusBlob(activationId, null);
        response.setEncryptedStatusBlob(null);
        return response;
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface. The method should be used to
     * acquire the activation status for PowerAuth standard RESTful API implementation purposes. The returned object
     * contains an encrypted activation status blob.
     *
     * @param activationId Activation Id to lookup information for.
     * @param challenge Cryptographic challenge for activation status blob encryption.
     * @return {@link GetActivationStatusResponse}
     */
    public GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) {
        GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        request.setChallenge(challenge);
        return this.getActivationStatus(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link GetActivationListForUserRequest} instance
     * @return {@link GetActivationListForUserResponse}
     */
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) {
        return (GetActivationListForUserResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     */
    public List<GetActivationListForUserResponse.Activations> getActivationListForUser(String userId) {
        GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(userId);
        return this.getActivationListForUser(request).getActivations();
    }

    /**
     * Call the lookupActivations method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link LookupActivationsRequest} instance
     * @return {@link LookupActivationsResponse}
     */
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) {
        return (LookupActivationsResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the lookupActivations method of the PowerAuth 3.0 Server SOAP interface.
     * @param userIds User IDs to be used in the activations query.
     * @param applicationIds Application IDs to be used in the activations query (optional).
     * @param timestampLastUsedBefore Last used timestamp to be used in the activations query, return all records where timestampLastUsed &lt; timestampLastUsedBefore (optional).
     * @param timestampLastUsedAfter Last used timestamp to be used in the activations query, return all records where timestampLastUsed &gt;= timestampLastUsedAfter (optional).
     * @param activationStatus Activation status to be used in the activations query (optional).
     * @return List of activation instances satisfying given query parameters.
     */
    public List<LookupActivationsResponse.Activations> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus) {
        LookupActivationsRequest request = new LookupActivationsRequest();
        request.getUserIds().addAll(userIds);
        if (request.getApplicationIds() != null) {
            request.getApplicationIds().addAll(applicationIds);
        }
        if (timestampLastUsedBefore != null) {
            request.setTimestampLastUsedBefore(calendarWithDate(timestampLastUsedBefore));
        }
        if (timestampLastUsedAfter != null) {
            request.setTimestampLastUsedAfter(calendarWithDate(timestampLastUsedAfter));
        }
        if (request.getActivationStatus() != null) {
            request.setActivationStatus(activationStatus);
        }
        return this.lookupActivations(request).getActivations();
    }

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link UpdateStatusForActivationsRequest} instance
     * @return {@link UpdateStatusForActivationsResponse}
     */
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) {
        return (UpdateStatusForActivationsResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the updateStatusForActivations method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationIds Identifiers of activations whose status should be updated.
     * @param activationStatus Activation status to be used.
     * @return Response indicating whether activation status update succeeded.
     */
    public UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) {
        UpdateStatusForActivationsRequest request = new UpdateStatusForActivationsRequest();
        request.getActivationIds().addAll(activationIds);
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        return this.updateStatusForActivations(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link RemoveActivationRequest} instance.
     * @return {@link RemoveActivationResponse}
     */
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
        return (RemoveActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be removed.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @return {@link RemoveActivationResponse}
     */
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId) {
        RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.removeActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link BlockActivationRequest} instance.
     * @return {@link BlockActivationResponse}
     */
    public BlockActivationResponse blockActivation(BlockActivationRequest request) {
        return (BlockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be blocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @param reason Reason why activation is being blocked.
     * @return {@link BlockActivationResponse}
     */
    public BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) {
        BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        request.setExternalUserId(externalUserId);
        return this.blockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link UnblockActivationRequest} instance.
     * @return {@link UnblockActivationResponse}
     */
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) {
        return (UnblockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be unblocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @return {@link UnblockActivationResponse}
     */
    public UnblockActivationResponse unblockActivation(String activationId, String externalUserId) {
        UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.unblockActivation(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link VaultUnlockRequest} instance
     * @return {@link VaultUnlockResponse}
     */
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
        return (VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation Id of an activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param signedData Data to be signed encoded in format as specified by PowerAuth data normalization.
     * @param signature Vault opening request signature.
     * @param signatureType Vault opening request signature type.
     * @param signatureVersion Signature version.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac MAC of key and data for ECIES.
     * @param nonce Nonce for ECIES.
     * @return {@link VaultUnlockResponse}
     */
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                           SignatureType signatureType, String signatureVersion, String signedData,
                                           String ephemeralPublicKey, String encryptedData, String mac, String nonce) {
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

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID.
     * @param data Data for offline signature.
     * @return {@link CreatePersonalizedOfflineSignaturePayloadResponse}
     */
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) {
        CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link CreatePersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link CreatePersonalizedOfflineSignaturePayloadResponse}
     */
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) {
        return (CreatePersonalizedOfflineSignaturePayloadResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param applicationId Application ID.
     * @param data Data for offline signature.
     * @return {@link CreateNonPersonalizedOfflineSignaturePayloadResponse}
     */
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) {
        CreateNonPersonalizedOfflineSignaturePayloadRequest request = new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link CreateNonPersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link CreateNonPersonalizedOfflineSignaturePayloadResponse}
     */
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) {
        return (CreateNonPersonalizedOfflineSignaturePayloadResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID.
     * @param data Data for signature.
     * @param signature Signature value.
     * @param allowBiometry Whether POSSESSION_BIOMETRY signature type is allowed during signature verification.
     * @return Offline signature verification response.
     */
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) {
        VerifyOfflineSignatureRequest request = new VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setAllowBiometry(allowBiometry);
        return verifyOfflineSignature(request);
    }

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link VerifyOfflineSignatureRequest} instance.
     * @return {@link VerifyOfflineSignatureResponse}
     */
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) {
        return (VerifyOfflineSignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link VerifySignatureRequest} instance.
     * @return {@link VerifySignatureResponse}
     */
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
        return (VerifySignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param data Data to be signed encoded in format as specified by PowerAuth data normalization.
     * @param signature Request signature.
     * @param signatureType Request signature type.
     * @param signatureVersion Signature version.
     * @param forcedSignatureVersion Forced signature version.
     * @return Verify signature and return SOAP response with the verification results.
     */
    public VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) {
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

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link VerifyECDSASignatureRequest} instance.
     * @return {@link VerifyECDSASignatureResponse}
     */
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) {
        return (VerifyECDSASignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data Data that were signed by ECDSA algorithm.
     * @param signature Request signature.
     * @return Verify ECDSA signature and return SOAP response with the verification results.
     */
    public VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) {
        VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link SignatureAuditRequest} instance.
     * @return {@link SignatureAuditResponse}
     */
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) {
        return (SignatureAuditResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface and get
     * signature audit log for all application of a given user.
     * @param userId User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link io.getlime.powerauth.soap.v3.SignatureAuditResponse.Items}.
     */
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface and get
     * signature audit log for a single application.
     * @param userId User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate Limit the results to given ending date (= "older than").
     * @return List of signature audit items. See: {@link io.getlime.powerauth.soap.v3.SignatureAuditResponse.Items}.
     */
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link ActivationHistoryRequest} instance.
     * @return {@link ActivationHistoryResponse}
     */
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) {
        return (ActivationHistoryResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getActivationHistory method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID.
     * @param startingDate Limit the results to given starting date (= "newer than").
     * @param endingDate Limit the results to given ending date (= "older than").
     * @return List of activation history items. See: {@link io.getlime.powerauth.soap.v3.ActivationHistoryResponse.Items}.
     */
    public List<ActivationHistoryResponse.Items> getActivationHistory(String activationId, Date startingDate, Date endingDate) {
        ActivationHistoryRequest request = new ActivationHistoryRequest();
        request.setActivationId(activationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getActivationHistory(request).getItems();
    }

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     * @param request {@link GetApplicationListRequest} instance.
     * @return {@link GetApplicationListResponse}
     */
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) {
        return (GetApplicationListResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the list of all applications that are registered in PowerAuth Server.
     * @return List of applications.
     */
    public List<GetApplicationListResponse.Applications> getApplicationList() {
        return this.getApplicationList(new GetApplicationListRequest()).getApplications();
    }

    /**
     * Return the detail of given application, including all application versions.
     * @param request {@link GetApplicationDetailRequest} instance.
     * @return {@link GetApplicationDetailResponse}
     */
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) {
        return (GetApplicationDetailResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the detail of an application with given ID, including the version list.
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     */
    public GetApplicationDetailResponse getApplicationDetail(Long applicationId) {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    /**
     * Get the detail of an application with given name, including the version list.
     * @param applicationName name of an application to fetch.
     * @return Application with given name, including the version list.
     */
    public GetApplicationDetailResponse getApplicationDetail(String applicationName) {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(applicationName);
        return this.getApplicationDetail(request);
    }

    /**
     * Lookup an application by application key.
     * @param request {@link LookupApplicationByAppKeyRequest} instance.
     * @return {@link LookupApplicationByAppKeyResponse}
     */
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) {
        return (LookupApplicationByAppKeyResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Lookup an application by application key.
     * @param applicationKey Application key.
     * @return Response with application ID.
     */
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) {
        LookupApplicationByAppKeyRequest request = new LookupApplicationByAppKeyRequest();
        request.setApplicationKey(applicationKey);
        return this.lookupApplicationByAppKey(request);
    }

    /**
     * Create a new application with given name.
     * @param request {@link CreateApplicationRequest} instance.
     * @return {@link CreateApplicationResponse}
     */
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) {
        return (CreateApplicationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new application with given name.
     * @param name Name of the new application.
     * @return Application with a given name.
     */
    public CreateApplicationResponse createApplication(String name) {
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param request {@link CreateApplicationVersionRequest} instance.
     * @return {@link CreateApplicationVersionResponse}
     */
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) {
        return (CreateApplicationVersionResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param applicationId ID of an application to create a version for.
     * @param versionName Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     */
    public CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) {
        CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param request {@link UnsupportApplicationVersionRequest} instance.
     * @return {@link UnsupportApplicationVersionResponse}
     */
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) {
        return (UnsupportApplicationVersionResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     */
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) {
        UnsupportApplicationVersionRequest request = new UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param request {@link SupportApplicationVersionRequest} instance.
     * @return {@link SupportApplicationVersionResponse}
     */
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) {
        return (SupportApplicationVersionResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Renew the support for a given application version.
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     */
    public SupportApplicationVersionResponse supportApplicationVersion(Long versionId) {
        SupportApplicationVersionRequest request = new SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    /**
     * Create a new integration with given name.
     * @param request Request specifying the integration name.
     * @return New integration information.
     */
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) {
        return (CreateIntegrationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new integration with given name.
     * @param name Integration name.
     * @return New integration information.
     */
    public CreateIntegrationResponse createIntegration(String name) {
        CreateIntegrationRequest request = new CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    /**
     * Get the list of integrations.
     * @param request SOAP request object.
     * @return List of integrations.
     */
    public GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) {
        return (GetIntegrationListResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the list of integrations.
     * @return List of integrations.
     */
    public List<GetIntegrationListResponse.Items> getIntegrationList() {
        return this.getIntegrationList(new GetIntegrationListRequest()).getItems();
    }

    /**
     * Remove integration with given ID.
     * @param request SOAP object with integration ID to be removed.
     * @return Removal status.
     */
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) {
        return (RemoveIntegrationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Remove integration with given ID.
     * @param id ID of integration to be removed.
     * @return Removal status.
     */
    public RemoveIntegrationResponse removeIntegration(String id) {
        RemoveIntegrationRequest request = new RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }

    /**
     * Create a new callback URL with given request object.
     * @param request SOAP request object with callback URL details.
     * @return Information about new callback URL object.
     */
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) {
        return (CreateCallbackUrlResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new callback URL with given parameters.
     * @param applicationId Application ID.
     * @param name Callback URL display name.
     * @param callbackUrl Callback URL value.
     * @return Information about new callback URL object.
     */
    public CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl) {
        CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        return this.createCallbackUrl(request);
    }

    /**
     * Get the response with list of callback URL objects.
     * @param request SOAP request object with application ID.
     * @return Response with the list of all callback URLs for given application.
     */
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) {
        return (GetCallbackUrlListResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the list of callback URL objects.
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     */
    public List<GetCallbackUrlListResponse.CallbackUrlList> getCallbackUrlList(Long applicationId) {
        GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return getCallbackUrlList(request).getCallbackUrlList();
    }

    /**
     * Remove callback URL.
     * @param request Remove callback URL request.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) {
        return (RemoveCallbackUrlResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Remove callback URL.
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) {
        RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }

    /**
     * Create a new token for basic token-based authentication.
     * @param request Request with token information.
     * @return Response with created token.
     */
    public CreateTokenResponse createToken(CreateTokenRequest request) {
        return (CreateTokenResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new token for basic token-based authentication.
     * @param activationId Activation ID for the activation that is associated with the token.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key used for response encryption.
     * @param encryptedData Encrypted request data.
     * @param mac MAC computed for request key and data.
     * @param nonce Nonce for ECIES.
     * @param signatureType Type of the signature used for validating the create request.
     * @return Response with created token.
     */
    public CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                           String encryptedData, String mac, String nonce, SignatureType signatureType) {
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

    /**
     * Validate credentials used for basic token-based authentication.
     * @param request Credentials to validate.
     * @return Response with the credentials validation status.
     */
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) {
        return (ValidateTokenResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Validate credentials used for basic token-based authentication.
     * @param tokenId Token ID.
     * @param nonce Random token nonce.
     * @param timestamp Token timestamp.
     * @param tokenDigest Token digest.
     * @return Response with the credentials validation status.
     */
    public ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setTokenDigest(tokenDigest);
        return validateToken(request);
    }

    /**
     * Remove token with given token ID.
     * @param request Request with token ID.
     * @return Response token removal result.
     */
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) {
        return (RemoveTokenResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Remove token with given token ID.
     * @param tokenId Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     */
    public RemoveTokenResponse removeToken(String tokenId, String activationId) {
        RemoveTokenRequest request = new RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request);
    }

    /**
     * Get ECIES decryptor parameters.
     * @param request Request for ECIES decryptor parameters.
     * @return ECIES decryptor parameters.
     */
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) {
        return (GetEciesDecryptorResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get ECIES decryptor parameters.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @return ECIES decryptor parameters.
     */
    public GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) {
        GetEciesDecryptorRequest request = new GetEciesDecryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        return getEciesDecryptor(request);
    }

    /**
     * Start upgrade of activations to version 3.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     */
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) {
        return (StartUpgradeResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Start upgrade of activations to version 3.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key used for response encryption.
     * @param encryptedData Encrypted request data.
     * @param mac MAC computed for request key and data.
     * @param nonce Nonce for ECIES.
     * @return Start upgrade response.
     */
    public StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                                 String encryptedData, String mac, String nonce) {
        StartUpgradeRequest request = new StartUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return startUpgrade(request);
    }

    /**
     * Commit upgrade of activations to version 3.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     */
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) {
        return (CommitUpgradeResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Commit upgrade of activations to version 3.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @return Commit upgrade response.
     */
    public CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) {
        CommitUpgradeRequest request = new CommitUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        return commitUpgrade(request);
    }

    /**
     * Create recovery code.
     * @param request Create recovery code request.
     * @return Create recovery coderesponse.
     */
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) {
        return (CreateRecoveryCodeResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create recovery code for user.
     * @param applicationId Application ID.
     * @param userId User ID.
     * @param pukCount Number of PUKs to create.
     * @return Create recovery code response.
     */
    public CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount) {
        CreateRecoveryCodeRequest request = new CreateRecoveryCodeRequest();
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setPukCount(pukCount);
        return createRecoveryCode(request);
    }

    /**
     * Confirm recovery code.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     */
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) {
        return (ConfirmRecoveryCodeResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Confirm recovery code.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac MAC of key and data for ECIES.
     * @param nonce Nonce for ECIES.
     * @return Confirm recovery code response.
     */
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                           String encryptedData, String mac, String nonce) {
        ConfirmRecoveryCodeRequest request = new ConfirmRecoveryCodeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return confirmRecoveryCode(request);
    }

    /**
     * Lookup recovery codes.
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     */
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) {
        return (LookupRecoveryCodesResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Lookup recovery codes.
     * @param userId User ID.
     * @param activationId Activation ID.
     * @param applicationId Application ID.
     * @param recoveryCodeStatus Recovery code status.
     * @param recoveryPukStatus Recovery PUK status.
     * @return Lookup recovery codes response.
     */
    public LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                           RecoveryCodeStatus recoveryCodeStatus, RecoveryPukStatus recoveryPukStatus) {
        LookupRecoveryCodesRequest request = new LookupRecoveryCodesRequest();
        request.setUserId(userId);
        request.setActivationId(activationId);
        request.setApplicationId(applicationId);
        request.setRecoveryCodeStatus(recoveryCodeStatus);
        request.setRecoveryPukStatus(recoveryPukStatus);
        return lookupRecoveryCodes(request);
    }

    /**
     * Revoke recovery codes.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     */
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) {
        return (RevokeRecoveryCodesResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Revoke recovery codes.
     * @param recoveryCodeIds Identifiers of recovery codes to revoke.
     * @return Revoke recovery code response.
     */
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) {
        RevokeRecoveryCodesRequest request = new RevokeRecoveryCodesRequest();
        request.getRecoveryCodeIds().addAll(recoveryCodeIds);
        return revokeRecoveryCodes(request);
    }

    /**
     * Create activation using recovery code.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     */
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) {
        return (RecoveryCodeActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create activation using recovery code.
     * @param recoveryCode Recovery code.
     * @param puk Recovery PUK.
     * @param applicationKey Application key.
     * @param maxFailureCount Maximum failure count.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac MAC of key and data for ECIES.
     * @param nonce nonce for ECIES.
     * @return Create activation using recovery code response.
     */
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                            String ephemeralPublicKey, String encryptedData, String mac, String nonce) {
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

    /**
     * Get recovery configuration.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     */
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) {
        return (GetRecoveryConfigResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get recovery configuration.
     * @param applicationId Application ID.
     * @return Get recovery configuration response.
     */
    public GetRecoveryConfigResponse getRecoveryConfig(Long applicationId) {
        GetRecoveryConfigRequest request = new GetRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        return getRecoveryConfig(request);
    }

    /**
     * Update recovery configuration.
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     */
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) {
        return (UpdateRecoveryConfigResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Update recovery configuration.
     * @param applicationId Application ID.
     * @param activationRecoveryEnabled Whether activation recovery is enabled.
     * @param recoveryPostcardEnabled Whether recovery postcard is enabled.
     * @param allowMultipleRecoveryCodes Whether multiple recovery codes are allowed.
     * @param remoteRecoveryPublicKeyBase64 Base64 encoded remote public key.
     * @return Update recovery configuration response.
     */
    public UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) {
        UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        request.setActivationRecoveryEnabled(activationRecoveryEnabled);
        request.setRecoveryPostcardEnabled(recoveryPostcardEnabled);
        request.setAllowMultipleRecoveryCodes(allowMultipleRecoveryCodes);
        request.setRemotePostcardPublicKey(remoteRecoveryPublicKeyBase64);
        return updateRecoveryConfig(request);
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
    public class PowerAuthServiceClientV2 {

        /**
         * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.PrepareActivationRequest} instance
         * @return {@link io.getlime.powerauth.soap.v2.PrepareActivationResponse}
         */
        public io.getlime.powerauth.soap.v2.PrepareActivationResponse prepareActivation(io.getlime.powerauth.soap.v2.PrepareActivationRequest request) {
            return (io.getlime.powerauth.soap.v2.PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        }

        /**
         * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
         * @param activationIdShort Short activation ID.
         * @param activationName Name of this activation.
         * @param activationNonce Activation nonce.
         * @param applicationKey Application key of a given application.
         * @param applicationSignature Signature proving a correct application is sending the data.
         * @param cDevicePublicKey Device public key encrypted with activation OTP.
         * @param extras Additional, application specific information.
         * @return {@link io.getlime.powerauth.soap.v2.PrepareActivationResponse}
         */
        public io.getlime.powerauth.soap.v2.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) {
            io.getlime.powerauth.soap.v2.PrepareActivationRequest request = new io.getlime.powerauth.soap.v2.PrepareActivationRequest();
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

        /**
         * Create a new activation directly, using the createActivation method of the PowerAuth 2.0 Server
         * SOAP interface.
         * @param request Create activation request.
         * @return Create activation response.
         */
        public io.getlime.powerauth.soap.v2.CreateActivationResponse createActivation(io.getlime.powerauth.soap.v2.CreateActivationRequest request) {
            return (io.getlime.powerauth.soap.v2.CreateActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        }

        /**
         * Call the createActivation method of the PowerAuth 2.0 Server SOAP interface.
         * @param userId User ID.
         * @param applicationKey Application key of a given application.
         * @param identity Identity fingerprint used during activation.
         * @param activationName Name of this activation.
         * @param activationNonce Activation nonce.
         * @param applicationSignature Signature proving a correct application is sending the data.
         * @param cDevicePublicKey Device public key encrypted with activation OTP.
         * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
         * @param extras Additional, application specific information.
         * @return {@link io.getlime.powerauth.soap.v2.CreateActivationResponse}
         */
        public io.getlime.powerauth.soap.v2.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) {
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

        /**
         * Call the createActivation method of the PowerAuth 2.0 Server SOAP interface.
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
         * @return {@link io.getlime.powerauth.soap.v2.CreateActivationResponse}
         */
        public io.getlime.powerauth.soap.v2.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) {
            io.getlime.powerauth.soap.v2.CreateActivationRequest request = new io.getlime.powerauth.soap.v2.CreateActivationRequest();
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

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.VaultUnlockRequest} instance
         * @return {@link io.getlime.powerauth.soap.v2.VaultUnlockResponse}
         */
        public io.getlime.powerauth.soap.v2.VaultUnlockResponse unlockVault(io.getlime.powerauth.soap.v2.VaultUnlockRequest request) {
            return (io.getlime.powerauth.soap.v2.VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        }

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
         * @param activationId Activation Id of an activation to be used for authentication.
         * @param applicationKey Application Key of an application related to the activation.
         * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
         * @param signature Vault opening request signature.
         * @param signatureType Vault opening request signature type.
         * @param reason Reason why vault is being unlocked.
         * @return {@link io.getlime.powerauth.soap.v2.VaultUnlockResponse}
         */
        public io.getlime.powerauth.soap.v2.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, io.getlime.powerauth.soap.v2.SignatureType signatureType, String reason) {
            io.getlime.powerauth.soap.v2.VaultUnlockRequest request = new io.getlime.powerauth.soap.v2.VaultUnlockRequest();
            request.setActivationId(activationId);
            request.setApplicationKey(applicationKey);
            request.setData(data);
            request.setSignature(signature);
            request.setSignatureType(signatureType);
            request.setReason(reason);
            return this.unlockVault(request);
        }

        /**
         * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyRequest} instance.
         * @return {@link io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyResponse}
         */
        public io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyRequest request) {
            return (io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        }

        /**
         * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
         * newly generated derived encryption key.
         * @param activationId Activation ID used for the key generation.
         * @return {@link io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyResponse}
         */
        public io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) {
            io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyRequest request = new io.getlime.powerauth.soap.v2.GetPersonalizedEncryptionKeyRequest();
            request.setActivationId(activationId);
            request.setSessionIndex(sessionIndex);
            return this.generatePersonalizedE2EEncryptionKey(request);
        }

        /**
         * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyRequest} instance.
         * @return {@link io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyResponse}
         */
        public io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyRequest request) {
            return (io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        }

        /**
         * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
         * newly generated derived encryption key.
         * @param applicationKey Application key of application used for the key generation.
         * @return {@link io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyResponse}
         */
        public io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) {
            io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyRequest request = new io.getlime.powerauth.soap.v2.GetNonPersonalizedEncryptionKeyRequest();
            request.setApplicationKey(applicationKey);
            request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
            request.setSessionIndex(sessionIndex);
            return this.generateNonPersonalizedE2EEncryptionKey(request);
        }


        /**
         * Create a new token for basic token-based authentication.
         * @param request Request with token information.
         * @return Response with created token.
         */
        public io.getlime.powerauth.soap.v2.CreateTokenResponse createToken(io.getlime.powerauth.soap.v2.CreateTokenRequest request) {
            return (io.getlime.powerauth.soap.v2.CreateTokenResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        }

        /**
         * Create a new token for basic token-based authentication.
         * @param activationId Activation ID for the activation that is associated with the token.
         * @param ephemeralPublicKey Ephemeral public key used for response encryption.
         * @param signatureType Type of the signature used for validating the create request.
         * @return Response with created token.
         */
        public io.getlime.powerauth.soap.v2.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, io.getlime.powerauth.soap.v2.SignatureType signatureType) {
            io.getlime.powerauth.soap.v2.CreateTokenRequest request = new io.getlime.powerauth.soap.v2.CreateTokenRequest();
            request.setActivationId(activationId);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setSignatureType(signatureType);
            return createToken(request);
        }

    }

}
