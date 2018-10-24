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

package io.getlime.security.powerauth.soap.axis.client;


import io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub;
import io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;

import javax.xml.namespace.QName;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Class implementing a PowerAuth SOAP service client based on provided WSDL
 * service description. This class uses Axis 2 under the hood.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthServiceClient {

    private PowerAuthPortV3ServiceStub clientStubV3;
    private PowerAuthPortV2ServiceStub clientStubV2;
    private boolean isAuthenticationEnabled;
    private PowerAuthServiceClientV2 serviceClientV2;

    /**
     * Create a SOAP service client with the default URL:
     *
     * - http://localhost:8080/powerauth-java-server/soap
     *
     * @throws AxisFault When the Axis2 setup fails.
     */
    public PowerAuthServiceClient() throws AxisFault {
        this.clientStubV3 = new PowerAuthPortV3ServiceStub();
        this.clientStubV2 = new PowerAuthPortV2ServiceStub();
        serviceClientV2 = new PowerAuthServiceClientV2();
    }

    /**
     * Create a SOAP service client with the URI provided in parameter.
     * @param serviceUri SOAP service URI.
     * @throws AxisFault When the Axis2 setup fails.
     */
    public PowerAuthServiceClient(String serviceUri) throws AxisFault {
        this.clientStubV3 = new PowerAuthPortV3ServiceStub(serviceUri);
        this.clientStubV2 = new PowerAuthPortV2ServiceStub(serviceUri);
        serviceClientV2 = new PowerAuthServiceClientV2();
    }

    /**
     * Create a SOAP service client with the provided stub instances.
     * @param clientStubV3 Axis2 client stub for version 3.0.
     * @param clientStubV2 Axis2 client stub for version 2.0.
     */
    public PowerAuthServiceClient(PowerAuthPortV3ServiceStub clientStubV3, PowerAuthPortV2ServiceStub clientStubV2) {
        this.clientStubV3 = clientStubV3;
        this.clientStubV2 = clientStubV2;
        serviceClientV2 = new PowerAuthServiceClientV2();
    }

    /**
     * Set the Axis2 client stub.
     * @param clientStubV3 Client stub.
     */
    public void setClientStubV3(PowerAuthPortV3ServiceStub clientStubV3) {
        this.clientStubV3 = clientStubV3;
    }

    /**
     * Get the Axis2 client stub.
     * @return Client stub.
     */
    public PowerAuthPortV3ServiceStub getClientStubV3() {
        return clientStubV3;
    }


    /**
     * Set the Axis2 client stub.
     * @param clientStubV2 Client stub.
     */
    public void setClientStubV2(PowerAuthPortV2ServiceStub clientStubV2) {
        this.clientStubV2 = clientStubV2;
    }

    /**
     * Get the Axis2 client stub.
     * @return Client stub.
     */
    public PowerAuthPortV2ServiceStub getClientStubV2() {
        return clientStubV2;
    }
    /**
     * Set the SOAP service endpoint URI.
     * @param uri SOAP service URI.
     */
    public void setServiceUri(String uri) {
        clientStubV3._getServiceClient().getOptions().setTo(new EndpointReference(uri));
        clientStubV2._getServiceClient().getOptions().setTo(new EndpointReference(uri));
    }

    /**
     * Enable UsernameToken authentication of the SOAP client (WS-Security).
     * @param username Username.
     * @param password Password.
     */
    public void enableAuthentication(String username, String password) {

        if (isAuthenticationEnabled) {
            return;
        }

        isAuthenticationEnabled = true;

        OMFactory omFactory = OMAbstractFactory.getOMFactory();
        OMElement omSecurityElement = omFactory.createOMElement(new QName( "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security", "wsse"), null);

        OMElement omUsernameToken = omFactory.createOMElement(new QName("", "UsernameToken", "wsse"), null);

        OMElement omUsername = omFactory.createOMElement(new QName("", "Username", "wsse"), null);
        omUsername.setText(username);

        OMElement omPassword = omFactory.createOMElement(new QName("", "Password", "wsse"), null);
        omPassword.addAttribute("Type","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText",null );
        omPassword.setText(password);

        omUsernameToken.addChild(omUsername);
        omUsernameToken.addChild(omPassword);
        omSecurityElement.addChild(omUsernameToken);

        clientStubV3._getServiceClient().addHeader(omSecurityElement);
        clientStubV2._getServiceClient().addHeader(omSecurityElement);

    }

    /**
     * Convert date to GregorianCalendar
     * @param date Date to be converted.
     * @return A new instance of {@link GregorianCalendar}.
     */
    private GregorianCalendar calendarWithDate(Date date) {
        GregorianCalendar c = new GregorianCalendar();
        c.setTime(date);
        return c;
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetSystemStatusRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetSystemStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetSystemStatusResponse getSystemStatus(PowerAuthPortV3ServiceStub.GetSystemStatusRequest request) throws RemoteException {
        return clientStubV3.getSystemStatus(request);
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetSystemStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetSystemStatusResponse getSystemStatus() throws RemoteException {
        PowerAuthPortV3ServiceStub.GetSystemStatusRequest request = new PowerAuthPortV3ServiceStub.GetSystemStatusRequest();
        return clientStubV3.getSystemStatus(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.InitActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.InitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.InitActivationResponse initActivation(PowerAuthPortV3ServiceStub.InitActivationRequest request) throws RemoteException {
        return clientStubV3.initActivation(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.InitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.InitActivationResponse initActivation(String userId, Long applicationId) throws RemoteException {
        return this.initActivation(userId, applicationId, null, null);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.InitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws RemoteException {
        PowerAuthPortV3ServiceStub.InitActivationRequest request = new PowerAuthPortV3ServiceStub.InitActivationRequest();
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
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.PrepareActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.PrepareActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.PrepareActivationResponse prepareActivation(PowerAuthPortV3ServiceStub.PrepareActivationRequest request) throws RemoteException {
        return clientStubV3.prepareActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationCode Activation code.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac Mac of key and data for ECIES.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.PrepareActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac) throws RemoteException {
        PowerAuthPortV3ServiceStub.PrepareActivationRequest request = new PowerAuthPortV3ServiceStub.PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        return this.prepareActivation(request);
    }

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth 3.0 Server
     * SOAP interface.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateActivationResponse createActivation(PowerAuthPortV3ServiceStub.CreateActivationRequest request) throws RemoteException {
        return clientStubV3.createActivation(request);
    }

    /**
     * Call the createActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID.
     * @param applicationKey Application key of a given application.
     * @param identity Identity fingerprint used during activation.
     * @param activationName Name of this activation.
     * @param activationNonce Activation nonce.
     * @param applicationSignature Signature proving a correct application is sending the data.
     * @param cDevicePublicKey Device public key encrypted with activation OTP.
     * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
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
     * Call the createActivation method of the PowerAuth 3.0 Server SOAP interface.
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
     * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
        throw new IllegalStateException("Not implemented yet.");
    }

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CommitActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CommitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CommitActivationResponse commitActivation(PowerAuthPortV3ServiceStub.CommitActivationRequest request) throws RemoteException {
        return clientStubV3.commitActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID for activation to be committed.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CommitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CommitActivationResponse commitActivation(String activationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.CommitActivationRequest request = new PowerAuthPortV3ServiceStub.CommitActivationRequest();
        request.setActivationId(activationId);
        return this.commitActivation(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetActivationStatusRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetActivationStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetActivationStatusResponse getActivationStatus(PowerAuthPortV3ServiceStub.GetActivationStatusRequest request) throws RemoteException {
        return clientStubV3.getActivationStatus(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation Id to lookup information for.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetActivationStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetActivationStatusResponse getActivationStatus(String activationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.GetActivationStatusRequest request = new PowerAuthPortV3ServiceStub.GetActivationStatusRequest();
        request.setActivationId(activationId);
        return this.getActivationStatus(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetActivationListForUserRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetActivationListForUserResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetActivationListForUserResponse getActivationListForUser(PowerAuthPortV3ServiceStub.GetActivationListForUserRequest request) throws RemoteException {
        return clientStubV3.getActivationListForUser(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortV3ServiceStub.Activations_type0> getActivationListForUser(String userId) throws RemoteException {
        PowerAuthPortV3ServiceStub.GetActivationListForUserRequest request = new PowerAuthPortV3ServiceStub.GetActivationListForUserRequest();
        request.setUserId(userId);
        return Arrays.asList(this.getActivationListForUser(request).getActivations());
    }

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.RemoveActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.RemoveActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.RemoveActivationResponse removeActivation(PowerAuthPortV3ServiceStub.RemoveActivationRequest request) throws RemoteException {
        return clientStubV3.removeActivation(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be removed.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.RemoveActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.RemoveActivationResponse removeActivation(String activationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.RemoveActivationRequest request = new PowerAuthPortV3ServiceStub.RemoveActivationRequest();
        request.setActivationId(activationId);
        return this.removeActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.BlockActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.BlockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.BlockActivationResponse blockActivation(PowerAuthPortV3ServiceStub.BlockActivationRequest request) throws RemoteException {
        return clientStubV3.blockActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be blocked.
     * @param reason Reason why activation is being blocked.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.BlockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.BlockActivationResponse blockActivation(String activationId, String reason) throws RemoteException {
        PowerAuthPortV3ServiceStub.BlockActivationRequest request = new PowerAuthPortV3ServiceStub.BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        return this.blockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.UnblockActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.UnblockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.UnblockActivationResponse unblockActivation(PowerAuthPortV3ServiceStub.UnblockActivationRequest request) throws RemoteException {
        return clientStubV3.unblockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be unblocked.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.UnblockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.UnblockActivationResponse unblockActivation(String activationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.UnblockActivationRequest request = new PowerAuthPortV3ServiceStub.UnblockActivationRequest();
        request.setActivationId(activationId);
        return this.unblockActivation(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VaultUnlockRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VaultUnlockResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VaultUnlockResponse unlockVault(PowerAuthPortV3ServiceStub.VaultUnlockRequest request) throws RemoteException {
        return clientStubV3.vaultUnlock(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation Id of an activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param signedData Data to be signed encoded in format as specified by PowerAuth data normalization.
     * @param signature Vault opening request signature.
     * @param signatureType Vault opening request signature type.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param encryptedData Encrypted data for ECIES.
     * @param mac MAC of key and data for ECIES.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VaultUnlockResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                                                      PowerAuthPortV3ServiceStub.SignatureType signatureType, String signedData,
                                                                      String ephemeralPublicKey, String encryptedData, String mac) throws RemoteException {
        PowerAuthPortV3ServiceStub.VaultUnlockRequest request = new PowerAuthPortV3ServiceStub.VaultUnlockRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setSignedData(signedData);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        return unlockVault(request);
    }

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID.
     * @param data Data for offline signature.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadRequest request = new PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(PowerAuthPortV3ServiceStub.CreatePersonalizedOfflineSignaturePayloadRequest request) throws RemoteException {
        return clientStubV3.createPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param applicationId Application ID.
     * @param data Data for offline signature.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadRequest request = new PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(PowerAuthPortV3ServiceStub.CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws RemoteException {
        return clientStubV3.createNonPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID.
     * @param data Data for signature.
     * @param signature Signature value.
     * @param signatureType Signature type (used factors).
     * @return Offline signature verification response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, PowerAuthPortV3ServiceStub.SignatureType signatureType) throws RemoteException {
        PowerAuthPortV3ServiceStub.VerifyOfflineSignatureRequest request = new PowerAuthPortV3ServiceStub.VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return verifyOfflineSignature(request);
    }

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VerifyOfflineSignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VerifyOfflineSignatureResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VerifyOfflineSignatureResponse verifyOfflineSignature(PowerAuthPortV3ServiceStub.VerifyOfflineSignatureRequest request) throws RemoteException {
        return clientStubV3.verifyOfflineSignature(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VerifySignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VerifySignatureResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VerifySignatureResponse verifySignature(PowerAuthPortV3ServiceStub.VerifySignatureRequest request) throws RemoteException {
        return clientStubV3.verifySignature(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param data Data to be signed encoded in format as specified by PowerAuth 3.0 data normalization.
     * @param signature Request signature.
     * @param signatureType Request signature type.
     * @return Verify signature and return SOAP response with the verification results.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, PowerAuthPortV3ServiceStub.SignatureType signatureType) throws RemoteException {
        PowerAuthPortV3ServiceStub.VerifySignatureRequest request = new PowerAuthPortV3ServiceStub.VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return this.verifySignature(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VerifyECDSASignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.VerifyECDSASignatureResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VerifyECDSASignatureResponse verifyECDSASignature(PowerAuthPortV3ServiceStub.VerifyECDSASignatureRequest request) throws RemoteException {
        return clientStubV3.verifyECDSASignature(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data Data that were signed by ECDSA algorithm.
     * @param signature Request signature.
     * @return Verify ECDSA signature and return SOAP response with the verification results.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws RemoteException {
        PowerAuthPortV3ServiceStub.VerifyECDSASignatureRequest request = new PowerAuthPortV3ServiceStub.VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.SignatureAuditRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.SignatureAuditResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.SignatureAuditResponse getSignatureAuditLog(PowerAuthPortV3ServiceStub.SignatureAuditRequest request) throws RemoteException {
        return clientStubV3.signatureAudit(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface and get
     * signature audit log for all application of a given user.
     * @param userId User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.Items_type1}
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortV3ServiceStub.Items_type1> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws RemoteException {
        PowerAuthPortV3ServiceStub.SignatureAuditRequest request = new PowerAuthPortV3ServiceStub.SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return Arrays.asList(this.getSignatureAuditLog(request).getItems());
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface and get
     * signature audit log for a single application.
     * @param userId User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.Items_type1}
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortV3ServiceStub.Items_type1> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws RemoteException {
        PowerAuthPortV3ServiceStub.SignatureAuditRequest request = new PowerAuthPortV3ServiceStub.SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return Arrays.asList(this.getSignatureAuditLog(request).getItems());
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 3.0 Server.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetApplicationListRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetApplicationListResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetApplicationListResponse getApplicationList(PowerAuthPortV3ServiceStub.GetApplicationListRequest request) throws RemoteException {
        return clientStubV3.getApplicationList(request);
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 3.0 Server.
     * @return List of applications.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortV3ServiceStub.Applications_type0> getApplicationList() throws RemoteException {
        PowerAuthPortV3ServiceStub.GetApplicationListRequest request = new PowerAuthPortV3ServiceStub.GetApplicationListRequest();
        return Arrays.asList(this.getApplicationList(request).getApplications());
    }

    /**
     * Return the detail of given application, including all application versions.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetApplicationDetailRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.GetApplicationDetailResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetApplicationDetailResponse getApplicationDetail(PowerAuthPortV3ServiceStub.GetApplicationDetailRequest request) throws RemoteException {
        return clientStubV3.getApplicationDetail(request);
    }

    /**
     * Get the detail of an application with given ID, including the version list.
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.GetApplicationDetailRequest request = new PowerAuthPortV3ServiceStub.GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    /**
     * Create a new application with given name.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateApplicationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateApplicationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateApplicationResponse createApplication(PowerAuthPortV3ServiceStub.CreateApplicationRequest request) throws RemoteException {
        return clientStubV3.createApplication(request);
    }

    /**
     * Create a new application with given name.
     * @param name Name of the new application.
     * @return Application with a given name.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateApplicationResponse createApplication(String name) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreateApplicationRequest request = new PowerAuthPortV3ServiceStub.CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.CreateApplicationVersionResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateApplicationVersionResponse createApplicationVersion(PowerAuthPortV3ServiceStub.CreateApplicationVersionRequest request) throws RemoteException {
        return clientStubV3.createApplicationVersion(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param applicationId ID of an application to create a version for.
     * @param versionName Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreateApplicationVersionRequest request = new PowerAuthPortV3ServiceStub.CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.UnsupportApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.UnsupportApplicationVersionResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.UnsupportApplicationVersionResponse unsupportApplicationVersion(PowerAuthPortV3ServiceStub.UnsupportApplicationVersionRequest request) throws RemoteException {
        return clientStubV3.unsupportApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws RemoteException {
        PowerAuthPortV3ServiceStub.UnsupportApplicationVersionRequest request = new PowerAuthPortV3ServiceStub.UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.SupportApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub.SupportApplicationVersionResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.SupportApplicationVersionResponse supportApplicationVersion(PowerAuthPortV3ServiceStub.SupportApplicationVersionRequest request) throws RemoteException {
        return clientStubV3.supportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws RemoteException {
        PowerAuthPortV3ServiceStub.SupportApplicationVersionRequest request = new PowerAuthPortV3ServiceStub.SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    /**
     * Create a new integration with given name.
     * @param request Request specifying the integration name.
     * @return New integration information.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateIntegrationResponse createIntegration(PowerAuthPortV3ServiceStub.CreateIntegrationRequest request) throws RemoteException {
        return clientStubV3.createIntegration(request);
    }

    /**
     * Create a new integration with given name.
     * @param name Integration name.
     * @return New integration information.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateIntegrationResponse createIntegration(String name) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreateIntegrationRequest request = new PowerAuthPortV3ServiceStub.CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    /**
     * Get the list of integrations.
     * @param request SOAP request object.
     * @return List of integrations.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetIntegrationListResponse getIntegrationList(PowerAuthPortV3ServiceStub.GetIntegrationListRequest request) throws RemoteException {
        return clientStubV3.getIntegrationList(request);
    }

    /**
     * Get the list of integrations.
     * @return List of integrations.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortV3ServiceStub.Items_type0> getIntegrationList() throws RemoteException {
        PowerAuthPortV3ServiceStub.GetIntegrationListRequest request = new PowerAuthPortV3ServiceStub.GetIntegrationListRequest();
        return Arrays.asList(this.getIntegrationList(request).getItems());
    }

    /**
     * Remove integration with given ID.
     * @param request SOAP object with integration ID to be removed.
     * @return Removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.RemoveIntegrationResponse removeIntegration(PowerAuthPortV3ServiceStub.RemoveIntegrationRequest request) throws RemoteException {
        return clientStubV3.removeIntegration(request);
    }

    /**
     * Remove integration with given ID.
     * @param id ID of integration to be removed.
     * @return Removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.RemoveIntegrationResponse removeIntegration(String id) throws RemoteException {
        PowerAuthPortV3ServiceStub.RemoveIntegrationRequest request = new PowerAuthPortV3ServiceStub.RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }


    /**
     * Create a new callback URL with given request object.
     * @param request SOAP request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateCallbackUrlResponse createCallbackUrl(PowerAuthPortV3ServiceStub.CreateCallbackUrlRequest request) throws RemoteException {
        return clientStubV3.createCallbackUrl(request);
    }

    /**
     * Create a new callback URL with given parameters.
     * @param applicationId Application ID.
     * @param name Callback URL display name.
     * @param callbackUrl Callback URL value.
     * @return Information about new callback URL object.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreateCallbackUrlRequest request = new PowerAuthPortV3ServiceStub.CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        return this.createCallbackUrl(request);
    }

    /**
     * Get the response with list of callback URL objects.
     * @param request SOAP request object with application ID.
     * @return Response with the list of all callback URLs for given application.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetCallbackUrlListResponse getCallbackUrlList(PowerAuthPortV3ServiceStub.GetCallbackUrlListRequest request) throws RemoteException {
        return clientStubV3.getCallbackUrlList(request);
    }

    /**
     * Get the list of callback URL objects.
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortV3ServiceStub.CallbackUrlList_type0> getCallbackUrlList(Long applicationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.GetCallbackUrlListRequest request = new PowerAuthPortV3ServiceStub.GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return Arrays.asList(getCallbackUrlList(request).getCallbackUrlList());
    }

    /**
     * Remove callback URL.
     * @param request Remove callback URL request.
     * @return Information about removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.RemoveCallbackUrlResponse removeCallbackUrl(PowerAuthPortV3ServiceStub.RemoveCallbackUrlRequest request) throws RemoteException {
        return clientStubV3.removeCallbackUrl(request);
    }

    /**
     * Remove callback URL.
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws RemoteException {
        PowerAuthPortV3ServiceStub.RemoveCallbackUrlRequest request = new PowerAuthPortV3ServiceStub.RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }


    /**
     * Create a new token for basic token-based authentication.
     * @param request Request with token information.
     * @return Response with created token.
     */
    public PowerAuthPortV3ServiceStub.CreateTokenResponse createToken(PowerAuthPortV3ServiceStub.CreateTokenRequest request) throws RemoteException {
        return clientStubV3.createToken(request);
    }

    /**
     * Create a new token for basic token-based authentication.
     * @param activationId Activation ID for the activation that is associated with the token.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key used for response encryption.
     * @param encryptedData Encrypted request data.
     * @param mac MAC computed for request key and data.
     * @param signatureType Type of the signature used for validating the create request.
     * @return Response with created token.
     */
    public PowerAuthPortV3ServiceStub.CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                      String encryptedData, String mac, PowerAuthPortV3ServiceStub.SignatureType signatureType) throws RemoteException {
        PowerAuthPortV3ServiceStub.CreateTokenRequest request = new PowerAuthPortV3ServiceStub.CreateTokenRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setSignatureType(signatureType);
        return createToken(request);
    }

    /**
     * Validate credentials used for basic token-based authentication.
     * @param request Credentials to validate.
     * @return Response with the credentials validation status.
     */
    public PowerAuthPortV3ServiceStub.ValidateTokenResponse validateToken(PowerAuthPortV3ServiceStub.ValidateTokenRequest request) throws RemoteException {
        return clientStubV3.validateToken(request);
    }

    /**
     * Validate credentials used for basic token-based authentication.
     * @param tokenId Token ID.
     * @param nonce Random token nonce.
     * @param timestamp Token timestamp.
     * @param tokenDigest Token digest.
     * @return Response with the credentials validation status.
     */
    public PowerAuthPortV3ServiceStub.ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws RemoteException {
        PowerAuthPortV3ServiceStub.ValidateTokenRequest request = new PowerAuthPortV3ServiceStub.ValidateTokenRequest();
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
    public PowerAuthPortV3ServiceStub.RemoveTokenResponse removeToken(PowerAuthPortV3ServiceStub.RemoveTokenRequest request) throws RemoteException {
        return clientStubV3.removeToken(request);
    }

    /**
     * Remove token with given token ID.
     * @param tokenId Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     */
    public PowerAuthPortV3ServiceStub.RemoveTokenResponse removeToken(String tokenId, String activationId) throws RemoteException {
        PowerAuthPortV3ServiceStub.RemoveTokenRequest request = new PowerAuthPortV3ServiceStub.RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request);
    }

    /**
     * Get ECIES decryptor parameters.
     * @param request Request for ECIES decryptor parameters.
     * @return ECIES decryptor parameters.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetEciesDecryptorResponse getEciesDecryptor(PowerAuthPortV3ServiceStub.GetEciesDecryptorRequest request) throws RemoteException {
        return clientStubV3.getEciesDecryptor(request);
    }

    /**
     * Get ECIES decryptor parameters.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @return ECIES decryptor parameters.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) throws RemoteException {
        PowerAuthPortV3ServiceStub.GetEciesDecryptorRequest request = new PowerAuthPortV3ServiceStub.GetEciesDecryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        return getEciesDecryptor(request);
    }

    /**
     * Start migration of activations to version 3.
     * @param request Start migration request.
     * @return Start migration response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.StartMigrationResponse startMigration(PowerAuthPortV3ServiceStub.StartMigrationRequest request) throws RemoteException {
        return clientStubV3.startMigration(request);
    }

    /**
     * Start migration of activations to version 3.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key used for response encryption.
     * @param encryptedData Encrypted request data.
     * @param mac MAC computed for request key and data.
     * @return Start migration response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.StartMigrationResponse startMigration(String activationId, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac) throws RemoteException {
        PowerAuthPortV3ServiceStub.StartMigrationRequest request = new PowerAuthPortV3ServiceStub.StartMigrationRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        return startMigration(request);
    }

    /**
     * Commit migration of activations to version 3.
     * @param request Commit migration request.
     * @return Commit migration response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CommitMigrationResponse commitMigration(PowerAuthPortV3ServiceStub.CommitMigrationRequest request) throws RemoteException {
        return clientStubV3.commitMigration(request);
    }

    /**
     * Commit migration of activations to version 3.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @return Commit migration response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortV3ServiceStub.CommitMigrationResponse commitMigration(String activationId, String applicationKey) throws RemoteException {
        PowerAuthPortV3ServiceStub.CommitMigrationRequest request = new PowerAuthPortV3ServiceStub.CommitMigrationRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        return commitMigration(request);
    }

    /**
     * Get the PowerAuth 2.0 client. This client will be deprecated in future release.
     *
     * @return PowerAuth 2.0 client.
     */
    public PowerAuthServiceClientV2 v2() {
        return serviceClientV2;
    }

    /**
     * Client with PowerAuth version 2.0 methods. This client will be deprecated in future release.
     */
    public class PowerAuthServiceClientV2 {

        /**
         * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.PrepareActivationRequest} instance
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.PrepareActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.PrepareActivationResponse prepareActivation(PowerAuthPortV2ServiceStub.PrepareActivationRequest request) throws RemoteException {
            return clientStubV2.prepareActivation(request);
        }

        /**
         * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
         * @param activationIdShort Short activation ID.
         * @param activationName Name of this activation.
         * @param activationNonce Activation nonce.
         * @param ephemeralPublicKey Ephemeral public key.
         * @param applicationKey Application key of a given application.
         * @param applicationSignature Signature proving a correct application is sending the data.
         * @param cDevicePublicKey Device public key encrypted with activation OTP.
         * @param extras Additional, application specific information.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.PrepareActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) throws RemoteException {
            PowerAuthPortV2ServiceStub.PrepareActivationRequest request = new PowerAuthPortV2ServiceStub.PrepareActivationRequest();
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
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.CreateActivationResponse createActivation(PowerAuthPortV2ServiceStub.CreateActivationRequest request) throws RemoteException {
            return clientStubV2.createActivation(request);
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
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.CreateActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
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
         * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
         * @param extras Additional, application specific information.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.CreateActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
            PowerAuthPortV2ServiceStub.CreateActivationRequest request = new PowerAuthPortV2ServiceStub.CreateActivationRequest();
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
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.VaultUnlockRequest} instance
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.VaultUnlockResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.VaultUnlockResponse unlockVault(PowerAuthPortV2ServiceStub.VaultUnlockRequest request) throws RemoteException {
            return clientStubV2.vaultUnlock(request);
        }

        /**
         * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
         * @param activationId Activation Id of an activation to be used for authentication.
         * @param applicationKey Application Key of an application related to the activation.
         * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
         * @param signature Vault opening request signature.
         * @param signatureType Vault opening request signature type.
         * @param reason Reason why vault is being unlocked.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.VaultUnlockResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, PowerAuthPortV2ServiceStub.SignatureType signatureType, String reason) throws RemoteException {
            PowerAuthPortV2ServiceStub.VaultUnlockRequest request = new PowerAuthPortV2ServiceStub.VaultUnlockRequest();
            request.setActivationId(activationId);
            request.setApplicationKey(applicationKey);
            request.setData(data);
            request.setSignature(signature);
            request.setSignatureType(signatureType);
            request.setReason(reason);
            return this.unlockVault(request);
        }

        /**
         * Call the generateE2EPersonalziedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyRequest} instance.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyRequest request) throws RemoteException {
            return clientStubV2.getPersonalizedEncryptionKey(request);
        }

        /**
         * Call the generateE2EPersonalziedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
         * newly generated derived encryption key.
         * @param activationId Activation ID used for the key generation.
         * @param sessionIndex Session index.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) throws RemoteException {
            PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyRequest request = new PowerAuthPortV2ServiceStub.GetPersonalizedEncryptionKeyRequest();
            request.setActivationId(activationId);
            request.setSessionIndex(sessionIndex);
            return this.generatePersonalizedE2EEncryptionKey(request);
        }

        /**
         * Call the generateE2ENonPersonalizedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyRequest} instance.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyRequest request) throws RemoteException {
            return clientStubV2.getNonPersonalizedEncryptionKey(request);
        }

        /**
         * Call the generateE2ENonPersonalizedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
         * newly generated derived encryption key.
         * @param applicationKey Application key related to application used for the key generation.
         * @param ephemeralPublicKeyBase64 Ephemeral public key.
         * @param sessionIndex Session index.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) throws RemoteException {
            PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyRequest request = new PowerAuthPortV2ServiceStub.GetNonPersonalizedEncryptionKeyRequest();
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
        public PowerAuthPortV2ServiceStub.CreateTokenResponse createToken(PowerAuthPortV2ServiceStub.CreateTokenRequest request) throws RemoteException {
            return clientStubV2.createToken(request);
        }

        /**
         * Create a new token for basic token-based authentication.
         * @param activationId Activation ID for the activation that is associated with the token.
         * @param ephemeralPublicKey Ephemeral public key used for response encryption.
         * @param signatureType Type of the signature used for validating the create request.
         * @return Response with created token.
         */
        public PowerAuthPortV2ServiceStub.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, PowerAuthPortV2ServiceStub.SignatureType signatureType) throws RemoteException {
            PowerAuthPortV2ServiceStub.CreateTokenRequest request = new PowerAuthPortV2ServiceStub.CreateTokenRequest();
            request.setActivationId(activationId);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setSignatureType(signatureType);
            return createToken(request);
        }

    }

}
