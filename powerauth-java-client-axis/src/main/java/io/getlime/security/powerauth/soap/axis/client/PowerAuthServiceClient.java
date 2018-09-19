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


import io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub;
import io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub;
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

    private PowerAuthPortServiceV3Stub clientStubV3;
    private PowerAuthPortServiceV2Stub clientStubV2;
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
        this.clientStubV3 = new PowerAuthPortServiceV3Stub();
        this.clientStubV2 = new PowerAuthPortServiceV2Stub();
        serviceClientV2 = new PowerAuthServiceClientV2();
    }

    /**
     * Create a SOAP service client with the URI provided in parameter.
     * @param serviceUri SOAP service URI.
     * @throws AxisFault When the Axis2 setup fails.
     */
    public PowerAuthServiceClient(String serviceUri) throws AxisFault {
        this.clientStubV3 = new PowerAuthPortServiceV3Stub(serviceUri);
        this.clientStubV2 = new PowerAuthPortServiceV2Stub(serviceUri);
        serviceClientV2 = new PowerAuthServiceClientV2();
    }

    /**
     * Create a SOAP service client with the provided stub instances.
     * @param clientStubV3 Axis2 client stub for version 3.0.
     * @param clientStubV2 Axis2 client stub for version 2.0.
     */
    public PowerAuthServiceClient(PowerAuthPortServiceV3Stub clientStubV3, PowerAuthPortServiceV2Stub clientStubV2) {
        this.clientStubV3 = clientStubV3;
        this.clientStubV2 = clientStubV2;
        serviceClientV2 = new PowerAuthServiceClientV2();
    }

    /**
     * Set the Axis2 client stub.
     * @param clientStubV3 Client stub.
     */
    public void setClientStubV3(PowerAuthPortServiceV3Stub clientStubV3) {
        this.clientStubV3 = clientStubV3;
    }

    /**
     * Get the Axis2 client stub.
     * @return Client stub.
     */
    public PowerAuthPortServiceV3Stub getClientStubV3() {
        return clientStubV3;
    }


    /**
     * Set the Axis2 client stub.
     * @param clientStubV2 Client stub.
     */
    public void setClientStubV2(PowerAuthPortServiceV2Stub clientStubV2) {
        this.clientStubV2 = clientStubV2;
    }

    /**
     * Get the Axis2 client stub.
     * @return Client stub.
     */
    public PowerAuthPortServiceV2Stub getClientStubV2() {
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
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetSystemStatusRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetSystemStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetSystemStatusResponse getSystemStatus(PowerAuthPortServiceV3Stub.GetSystemStatusRequest request) throws RemoteException {
        return clientStubV3.getSystemStatus(request);
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetSystemStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetSystemStatusResponse getSystemStatus() throws RemoteException {
        PowerAuthPortServiceV3Stub.GetSystemStatusRequest request = new PowerAuthPortServiceV3Stub.GetSystemStatusRequest();
        return clientStubV3.getSystemStatus(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.InitActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.InitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.InitActivationResponse initActivation(PowerAuthPortServiceV3Stub.InitActivationRequest request) throws RemoteException {
        return clientStubV3.initActivation(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.InitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.InitActivationResponse initActivation(String userId, Long applicationId) throws RemoteException {
        return this.initActivation(userId, applicationId, null, null);
    }

    /**
     * Call the initActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.InitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws RemoteException {
        PowerAuthPortServiceV3Stub.InitActivationRequest request = new PowerAuthPortServiceV3Stub.InitActivationRequest();
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
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.PrepareActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.PrepareActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.PrepareActivationResponse prepareActivation(PowerAuthPortServiceV3Stub.PrepareActivationRequest request) throws RemoteException {
        return clientStubV3.prepareActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationIdShort Short activation ID.
     * @param activationName Name of this activation.
     * @param activationNonce Activation nonce.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param applicationKey Application key of a given application.
     * @param applicationSignature Signature proving a correct application is sending the data.
     * @param cDevicePublicKey Device public key encrypted with activation OTP.
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.PrepareActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) throws RemoteException {
        throw new IllegalStateException("Not implemented yet.");
    }

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth 3.0 Server
     * SOAP interface.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateActivationResponse createActivation(PowerAuthPortServiceV3Stub.CreateActivationRequest request) throws RemoteException {
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
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
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
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
        throw new IllegalStateException("Not implemented yet.");
    }

    /**
     * Call the commitActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CommitActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CommitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CommitActivationResponse commitActivation(PowerAuthPortServiceV3Stub.CommitActivationRequest request) throws RemoteException {
        return clientStubV3.commitActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID for activation to be committed.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CommitActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CommitActivationResponse commitActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.CommitActivationRequest request = new PowerAuthPortServiceV3Stub.CommitActivationRequest();
        request.setActivationId(activationId);
        return this.commitActivation(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetActivationStatusRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetActivationStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetActivationStatusResponse getActivationStatus(PowerAuthPortServiceV3Stub.GetActivationStatusRequest request) throws RemoteException {
        return clientStubV3.getActivationStatus(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation Id to lookup information for.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetActivationStatusResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetActivationStatusResponse getActivationStatus(String activationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.GetActivationStatusRequest request = new PowerAuthPortServiceV3Stub.GetActivationStatusRequest();
        request.setActivationId(activationId);
        return this.getActivationStatus(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetActivationListForUserRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetActivationListForUserResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetActivationListForUserResponse getActivationListForUser(PowerAuthPortServiceV3Stub.GetActivationListForUserRequest request) throws RemoteException {
        return clientStubV3.getActivationListForUser(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 3.0 Server SOAP interface.
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortServiceV3Stub.Activations_type0> getActivationListForUser(String userId) throws RemoteException {
        PowerAuthPortServiceV3Stub.GetActivationListForUserRequest request = new PowerAuthPortServiceV3Stub.GetActivationListForUserRequest();
        request.setUserId(userId);
        return Arrays.asList(this.getActivationListForUser(request).getActivations());
    }

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.RemoveActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.RemoveActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.RemoveActivationResponse removeActivation(PowerAuthPortServiceV3Stub.RemoveActivationRequest request) throws RemoteException {
        return clientStubV3.removeActivation(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be removed.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.RemoveActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.RemoveActivationResponse removeActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.RemoveActivationRequest request = new PowerAuthPortServiceV3Stub.RemoveActivationRequest();
        request.setActivationId(activationId);
        return this.removeActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.BlockActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.BlockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.BlockActivationResponse blockActivation(PowerAuthPortServiceV3Stub.BlockActivationRequest request) throws RemoteException {
        return clientStubV3.blockActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be blocked.
     * @param reason Reason why activation is being blocked.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.BlockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.BlockActivationResponse blockActivation(String activationId, String reason) throws RemoteException {
        PowerAuthPortServiceV3Stub.BlockActivationRequest request = new PowerAuthPortServiceV3Stub.BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        return this.blockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.UnblockActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.UnblockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.UnblockActivationResponse unblockActivation(PowerAuthPortServiceV3Stub.UnblockActivationRequest request) throws RemoteException {
        return clientStubV3.unblockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be unblocked.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.UnblockActivationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.UnblockActivationResponse unblockActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.UnblockActivationRequest request = new PowerAuthPortServiceV3Stub.UnblockActivationRequest();
        request.setActivationId(activationId);
        return this.unblockActivation(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VaultUnlockRequest} instance
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VaultUnlockResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.VaultUnlockResponse unlockVault(PowerAuthPortServiceV3Stub.VaultUnlockRequest request) throws RemoteException {
        return clientStubV3.vaultUnlock(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation Id of an activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param data Data to be signed encoded in format as specified by PowerAuth 3.0 data normalization.
     * @param signature Vault opening request signature.
     * @param signatureType Vault opening request signature type.
     * @param reason Reason why vault is being unlocked.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VaultUnlockResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, PowerAuthPortServiceV3Stub.SignatureType signatureType, String reason) throws RemoteException {
        throw new IllegalStateException("Not implemented yet.");
    }

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param activationId Activation ID.
     * @param data Data for offline signature.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadRequest request = new PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(PowerAuthPortServiceV3Stub.CreatePersonalizedOfflineSignaturePayloadRequest request) throws RemoteException {
        return clientStubV3.createPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param applicationId Application ID.
     * @param data Data for offline signature.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadRequest request = new PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request);
    }

    /**
     * Call the createNonPersonalizedOfflineSignaturePayload method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(PowerAuthPortServiceV3Stub.CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws RemoteException {
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
    public PowerAuthPortServiceV3Stub.VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, PowerAuthPortServiceV3Stub.SignatureType signatureType) throws RemoteException {
        PowerAuthPortServiceV3Stub.VerifyOfflineSignatureRequest request = new PowerAuthPortServiceV3Stub.VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return verifyOfflineSignature(request);
    }

    /**
     * Verify offline signature by calling verifyOfflineSignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VerifyOfflineSignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VerifyOfflineSignatureResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.VerifyOfflineSignatureResponse verifyOfflineSignature(PowerAuthPortServiceV3Stub.VerifyOfflineSignatureRequest request) throws RemoteException {
        return clientStubV3.verifyOfflineSignature(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VerifySignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VerifySignatureResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.VerifySignatureResponse verifySignature(PowerAuthPortServiceV3Stub.VerifySignatureRequest request) throws RemoteException {
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
    public PowerAuthPortServiceV3Stub.VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, PowerAuthPortServiceV3Stub.SignatureType signatureType) throws RemoteException {
        PowerAuthPortServiceV3Stub.VerifySignatureRequest request = new PowerAuthPortServiceV3Stub.VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return this.verifySignature(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VerifyECDSASignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.VerifyECDSASignatureResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.VerifyECDSASignatureResponse verifyECDSASignature(PowerAuthPortServiceV3Stub.VerifyECDSASignatureRequest request) throws RemoteException {
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
    public PowerAuthPortServiceV3Stub.VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws RemoteException {
        PowerAuthPortServiceV3Stub.VerifyECDSASignatureRequest request = new PowerAuthPortServiceV3Stub.VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 3.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.SignatureAuditRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.SignatureAuditResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.SignatureAuditResponse getSignatureAuditLog(PowerAuthPortServiceV3Stub.SignatureAuditRequest request) throws RemoteException {
        return clientStubV3.signatureAudit(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 3.0 Server SOAP interface and get
     * signature audit log for all application of a given user.
     * @param userId User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.Items_type1}
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortServiceV3Stub.Items_type1> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws RemoteException {
        PowerAuthPortServiceV3Stub.SignatureAuditRequest request = new PowerAuthPortServiceV3Stub.SignatureAuditRequest();
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
     * @return List of signature audit items {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.Items_type1}
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortServiceV3Stub.Items_type1> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws RemoteException {
        PowerAuthPortServiceV3Stub.SignatureAuditRequest request = new PowerAuthPortServiceV3Stub.SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return Arrays.asList(this.getSignatureAuditLog(request).getItems());
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 3.0 Server.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetApplicationListRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetApplicationListResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetApplicationListResponse getApplicationList(PowerAuthPortServiceV3Stub.GetApplicationListRequest request) throws RemoteException {
        return clientStubV3.getApplicationList(request);
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 3.0 Server.
     * @return List of applications.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortServiceV3Stub.Applications_type0> getApplicationList() throws RemoteException {
        PowerAuthPortServiceV3Stub.GetApplicationListRequest request = new PowerAuthPortServiceV3Stub.GetApplicationListRequest();
        return Arrays.asList(this.getApplicationList(request).getApplications());
    }

    /**
     * Return the detail of given application, including all application versions.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetApplicationDetailRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.GetApplicationDetailResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetApplicationDetailResponse getApplicationDetail(PowerAuthPortServiceV3Stub.GetApplicationDetailRequest request) throws RemoteException {
        return clientStubV3.getApplicationDetail(request);
    }

    /**
     * Get the detail of an application with given ID, including the version list.
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.GetApplicationDetailRequest request = new PowerAuthPortServiceV3Stub.GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    /**
     * Create a new application with given name.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateApplicationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateApplicationResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateApplicationResponse createApplication(PowerAuthPortServiceV3Stub.CreateApplicationRequest request) throws RemoteException {
        return clientStubV3.createApplication(request);
    }

    /**
     * Create a new application with given name.
     * @param name Name of the new application.
     * @return Application with a given name.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateApplicationResponse createApplication(String name) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreateApplicationRequest request = new PowerAuthPortServiceV3Stub.CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.CreateApplicationVersionResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateApplicationVersionResponse createApplicationVersion(PowerAuthPortServiceV3Stub.CreateApplicationVersionRequest request) throws RemoteException {
        return clientStubV3.createApplicationVersion(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param applicationId ID of an application to create a version for.
     * @param versionName Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreateApplicationVersionRequest request = new PowerAuthPortServiceV3Stub.CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.UnsupportApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.UnsupportApplicationVersionResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.UnsupportApplicationVersionResponse unsupportApplicationVersion(PowerAuthPortServiceV3Stub.UnsupportApplicationVersionRequest request) throws RemoteException {
        return clientStubV3.unsupportApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws RemoteException {
        PowerAuthPortServiceV3Stub.UnsupportApplicationVersionRequest request = new PowerAuthPortServiceV3Stub.UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param request {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.SupportApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.v3.PowerAuthPortServiceV3Stub.SupportApplicationVersionResponse}
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.SupportApplicationVersionResponse supportApplicationVersion(PowerAuthPortServiceV3Stub.SupportApplicationVersionRequest request) throws RemoteException {
        return clientStubV3.supportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws RemoteException {
        PowerAuthPortServiceV3Stub.SupportApplicationVersionRequest request = new PowerAuthPortServiceV3Stub.SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    /**
     * Create a new integration with given name.
     * @param request Request specifying the integration name.
     * @return New integration information.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateIntegrationResponse createIntegration(PowerAuthPortServiceV3Stub.CreateIntegrationRequest request) throws RemoteException {
        return clientStubV3.createIntegration(request);
    }

    /**
     * Create a new integration with given name.
     * @param name Integration name.
     * @return New integration information.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateIntegrationResponse createIntegration(String name) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreateIntegrationRequest request = new PowerAuthPortServiceV3Stub.CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    /**
     * Get the list of integrations.
     * @param request SOAP request object.
     * @return List of integrations.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.GetIntegrationListResponse getIntegrationList(PowerAuthPortServiceV3Stub.GetIntegrationListRequest request) throws RemoteException {
        return clientStubV3.getIntegrationList(request);
    }

    /**
     * Get the list of integrations.
     * @return List of integrations.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortServiceV3Stub.Items_type0> getIntegrationList() throws RemoteException {
        PowerAuthPortServiceV3Stub.GetIntegrationListRequest request = new PowerAuthPortServiceV3Stub.GetIntegrationListRequest();
        return Arrays.asList(this.getIntegrationList(request).getItems());
    }

    /**
     * Remove integration with given ID.
     * @param request SOAP object with integration ID to be removed.
     * @return Removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.RemoveIntegrationResponse removeIntegration(PowerAuthPortServiceV3Stub.RemoveIntegrationRequest request) throws RemoteException {
        return clientStubV3.removeIntegration(request);
    }

    /**
     * Remove integration with given ID.
     * @param id ID of integration to be removed.
     * @return Removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.RemoveIntegrationResponse removeIntegration(String id) throws RemoteException {
        PowerAuthPortServiceV3Stub.RemoveIntegrationRequest request = new PowerAuthPortServiceV3Stub.RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }


    /**
     * Create a new callback URL with given request object.
     * @param request SOAP request object with callback URL details.
     * @return Information about new callback URL object.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.CreateCallbackUrlResponse createCallbackUrl(PowerAuthPortServiceV3Stub.CreateCallbackUrlRequest request) throws RemoteException {
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
    public PowerAuthPortServiceV3Stub.CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreateCallbackUrlRequest request = new PowerAuthPortServiceV3Stub.CreateCallbackUrlRequest();
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
    public PowerAuthPortServiceV3Stub.GetCallbackUrlListResponse getCallbackUrlList(PowerAuthPortServiceV3Stub.GetCallbackUrlListRequest request) throws RemoteException {
        return clientStubV3.getCallbackUrlList(request);
    }

    /**
     * Get the list of callback URL objects.
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     * @throws RemoteException In case of a business logic error.
     */
    public List<PowerAuthPortServiceV3Stub.CallbackUrlList_type0> getCallbackUrlList(Long applicationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.GetCallbackUrlListRequest request = new PowerAuthPortServiceV3Stub.GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return Arrays.asList(getCallbackUrlList(request).getCallbackUrlList());
    }

    /**
     * Remove callback URL.
     * @param request Remove callback URL request.
     * @return Information about removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.RemoveCallbackUrlResponse removeCallbackUrl(PowerAuthPortServiceV3Stub.RemoveCallbackUrlRequest request) throws RemoteException {
        return clientStubV3.removeCallbackUrl(request);
    }

    /**
     * Remove callback URL.
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     * @throws RemoteException In case of a business logic error.
     */
    public PowerAuthPortServiceV3Stub.RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws RemoteException {
        PowerAuthPortServiceV3Stub.RemoveCallbackUrlRequest request = new PowerAuthPortServiceV3Stub.RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }


    /**
     * Create a new token for basic token-based authentication.
     * @param request Request with token information.
     * @return Response with created token.
     */
    public PowerAuthPortServiceV3Stub.CreateTokenResponse createToken(PowerAuthPortServiceV3Stub.CreateTokenRequest request) throws RemoteException {
        return clientStubV3.createToken(request);
    }

    /**
     * Create a new token for basic token-based authentication.
     * @param activationId Activation ID for the activation that is associated with the token.
     * @param ephemeralPublicKey Ephemeral public key used for response encryption.
     * @param signatureType Type of the signature used for validating the create request.
     * @return Response with created token.
     */
    public PowerAuthPortServiceV3Stub.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, PowerAuthPortServiceV3Stub.SignatureType signatureType) throws RemoteException {
        PowerAuthPortServiceV3Stub.CreateTokenRequest request = new PowerAuthPortServiceV3Stub.CreateTokenRequest();
        request.setActivationId(activationId);
        request.setEphemeralKey(ephemeralPublicKey);
        request.setSignatureType(signatureType);
        return createToken(request);
    }

    /**
     * Validate credentials used for basic token-based authentication.
     * @param request Credentials to validate.
     * @return Response with the credentials validation status.
     */
    public PowerAuthPortServiceV3Stub.ValidateTokenResponse validateToken(PowerAuthPortServiceV3Stub.ValidateTokenRequest request) throws RemoteException {
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
    public PowerAuthPortServiceV3Stub.ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws RemoteException {
        PowerAuthPortServiceV3Stub.ValidateTokenRequest request = new PowerAuthPortServiceV3Stub.ValidateTokenRequest();
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
    public PowerAuthPortServiceV3Stub.RemoveTokenResponse removeToken(PowerAuthPortServiceV3Stub.RemoveTokenRequest request) throws RemoteException {
        return clientStubV3.removeToken(request);
    }

    /**
     * Remove token with given token ID.
     * @param tokenId Token ID.
     * @param activationId ActivationId ID.
     * @return Response token removal result.
     */
    public PowerAuthPortServiceV3Stub.RemoveTokenResponse removeToken(String tokenId, String activationId) throws RemoteException {
        PowerAuthPortServiceV3Stub.RemoveTokenRequest request = new PowerAuthPortServiceV3Stub.RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request);
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
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.PrepareActivationRequest} instance
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.PrepareActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.PrepareActivationResponse prepareActivation(PowerAuthPortServiceV2Stub.PrepareActivationRequest request) throws RemoteException {
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
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.PrepareActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) throws RemoteException {
            PowerAuthPortServiceV2Stub.PrepareActivationRequest request = new PowerAuthPortServiceV2Stub.PrepareActivationRequest();
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
        public PowerAuthPortServiceV2Stub.CreateActivationResponse createActivation(PowerAuthPortServiceV2Stub.CreateActivationRequest request) throws RemoteException {
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
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.CreateActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
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
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.CreateActivationResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
            PowerAuthPortServiceV2Stub.CreateActivationRequest request = new PowerAuthPortServiceV2Stub.CreateActivationRequest();
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
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.VaultUnlockRequest} instance
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.VaultUnlockResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.VaultUnlockResponse unlockVault(PowerAuthPortServiceV2Stub.VaultUnlockRequest request) throws RemoteException {
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
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.VaultUnlockResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, PowerAuthPortServiceV2Stub.SignatureType signatureType, String reason) throws RemoteException {
            PowerAuthPortServiceV2Stub.VaultUnlockRequest request = new PowerAuthPortServiceV2Stub.VaultUnlockRequest();
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
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyRequest} instance.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyRequest request) throws RemoteException {
            return clientStubV2.getPersonalizedEncryptionKey(request);
        }

        /**
         * Call the generateE2EPersonalziedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
         * newly generated derived encryption key.
         * @param activationId Activation ID used for the key generation.
         * @param sessionIndex Session index.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) throws RemoteException {
            PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyRequest request = new PowerAuthPortServiceV2Stub.GetPersonalizedEncryptionKeyRequest();
            request.setActivationId(activationId);
            request.setSessionIndex(sessionIndex);
            return this.generatePersonalizedE2EEncryptionKey(request);
        }

        /**
         * Call the generateE2ENonPersonalizedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
         * @param request {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyRequest} instance.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyRequest request) throws RemoteException {
            return clientStubV2.getNonPersonalizedEncryptionKey(request);
        }

        /**
         * Call the generateE2ENonPersonalizedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
         * newly generated derived encryption key.
         * @param applicationKey Application key related to application used for the key generation.
         * @param ephemeralPublicKeyBase64 Ephemeral public key.
         * @param sessionIndex Session index.
         * @return {@link io.getlime.powerauth.soap.v2.PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyResponse}
         * @throws RemoteException In case of a business logic error.
         */
        public PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) throws RemoteException {
            PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyRequest request = new PowerAuthPortServiceV2Stub.GetNonPersonalizedEncryptionKeyRequest();
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
        public PowerAuthPortServiceV2Stub.CreateTokenResponse createToken(PowerAuthPortServiceV2Stub.CreateTokenRequest request) throws RemoteException {
            return clientStubV2.createToken(request);
        }

        /**
         * Create a new token for basic token-based authentication.
         * @param activationId Activation ID for the activation that is associated with the token.
         * @param ephemeralPublicKey Ephemeral public key used for response encryption.
         * @param signatureType Type of the signature used for validating the create request.
         * @return Response with created token.
         */
        public PowerAuthPortServiceV2Stub.CreateTokenResponse createToken(String activationId, String ephemeralPublicKey, PowerAuthPortServiceV2Stub.SignatureType signatureType) throws RemoteException {
            PowerAuthPortServiceV2Stub.CreateTokenRequest request = new PowerAuthPortServiceV2Stub.CreateTokenRequest();
            request.setActivationId(activationId);
            request.setEphemeralPublicKey(ephemeralPublicKey);
            request.setSignatureType(signatureType);
            return createToken(request);
        }

    }

}
