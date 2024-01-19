/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.controller.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Configuration class for PowerAuth Controller tests.
 * <p>
 * This class provides configuration settings and helper methods
 * for testing PowerAuth Controller. It includes methods for initializing
 * test data, creating applications, managing activations, and handling
 * other necessary setup for conducting tests effectively.
 * </p>
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Configuration
public class PowerAuthControllerTestConfig {

    private static final String POWERAUTH_REST_URL = "http://localhost:8080/rest";
    private static final String PUBLIC_KEY_RECOVERY_POSTCARD_BASE64 = "BABXgGoj4Lizl3GN0rjrtileEEwekFkpX1ERS9yyYjyuM1Iqdti3ihtATBxk5XGvjetPO1YC+qXciUYjIsETtbI=";
    protected static final String USER_ID = "test-user";
    protected static final String DATA = "A2";
    protected static final String CALLBACK_NAME = UUID.randomUUID().toString();
    protected static final String CALLBACK_URL = "http://test.test";
    protected static final String PROTOCOL_VERSION = "3.2";

    private String applicationId;
    private String applicationVersionId;
    private String applicationKey;
    private String applicationSecret;
    private String masterPublicKey;
    private String applicationVersion = "default" + "_" + System.currentTimeMillis();
    private final String applicationName = "Pa_tests_component";
    private Long loginOperationTemplateId;
    private String loginOperationTemplateName;
    private String activationId;
    private String activationCode;
    private String activationName;

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(final String applicationId) {
        this.applicationId = applicationId;
    }

    public String getApplicationVersionId() {
        return applicationVersionId;
    }

    public void setApplicationVersionId(final String applicationVersionId) {
        this.applicationVersionId = applicationVersionId;
    }

    public String getApplicationKey() {
        return applicationKey;
    }

    public void setApplicationKey(final String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    public void setApplicationSecret(final String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    public String getMasterPublicKey() {
        return masterPublicKey;
    }

    public void setMasterPublicKey(final String masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    public String getApplicationVersion() {
        return applicationVersion;
    }

    public void setApplicationVersion(final String applicationVersion) {
        this.applicationVersion = applicationVersion;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public Long getLoginOperationTemplateId() {
        return loginOperationTemplateId;
    }

    public void setLoginOperationTemplateId(final Long loginOperationTemplateId) {
        this.loginOperationTemplateId = loginOperationTemplateId;
    }

    public String getLoginOperationTemplateName() {
        return loginOperationTemplateName;
    }

    public void setLoginOperationTemplateName(final String loginOperationTemplateName) {
        this.loginOperationTemplateName = loginOperationTemplateName;
    }

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(final String activationId) {
        this.activationId = activationId;
    }

    public void setActivationCode(final String activationCode) {
        this.activationCode = activationCode;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationName(final String activationName) {
        this.activationName = activationName;
    }

    public String getActivationName() {
        return activationName;
    }

    /**
     * Creates and configures a new {@link PowerAuthClient} bean.
     * <p>
     * The method configures and returns a PowerAuthClient instance for interacting with
     * the PowerAuth Server. It sets up the client with the necessary configurations such as
     * accepting invalid SSL certificates for testing purposes.
     *
     * @return A configured instance of PowerAuthClient
     * @throws Exception if there is an issue creating the PowerAuthClient instance
     */
    @Bean
    public PowerAuthClient powerAuthClient() throws Exception {
        final PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
        config.setAcceptInvalidSslCertificate(true);
        return new PowerAuthRestClient(POWERAUTH_REST_URL);
    }


    /*
     *****************************************************************
     *                                                               *
     *                   HELPER INITIALIZATION METHODS               *
     *                                                               *
     *****************************************************************
     */


    /**
     * Creates a request object for creating an operation.
     * <p>
     * This helper method constructs and returns an {@link OperationCreateRequest} with
     * predefined application ID, template name, user ID, and proximity OTP settings.
     *
     * @param proximityOtpEnabled a boolean indicating whether proximity OTP is enabled
     * @return a configured {@link OperationCreateRequest} instance
     */
    private OperationCreateRequest createOperationCreateRequest(final boolean proximityOtpEnabled) {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of(getApplicationId()));
        operationCreateRequest.setTemplateName(getLoginOperationTemplateName());
        operationCreateRequest.setUserId(USER_ID);
        operationCreateRequest.setProximityCheckEnabled(proximityOtpEnabled);
        return operationCreateRequest;
    }

    /**
     * Creates a request object for creating a callback URL.
     * <p>
     * This helper method constructs and returns a {@link CreateCallbackUrlRequest} with
     * predefined callback URL, name, type, application ID, and other settings.
     *
     * @return a configured {@link CreateCallbackUrlRequest} instance
     */
    private CreateCallbackUrlRequest createCallbackUrlRequest() {
        final CreateCallbackUrlRequest callbackUrlRequest = new CreateCallbackUrlRequest();
        callbackUrlRequest.setCallbackUrl(CALLBACK_URL);
        callbackUrlRequest.setName(CALLBACK_NAME);
        callbackUrlRequest.setType(CallbackUrlType.ACTIVATION_STATUS_CHANGE.name());
        callbackUrlRequest.setApplicationId(getApplicationId());
        callbackUrlRequest.setAttributes(Collections.singletonList("activationId"));
        callbackUrlRequest.setAuthentication(null);
        return callbackUrlRequest;
    }

    /**
     * Initializes a new activation and verifies its status.
     * <p>
     * This method creates an activation for the provided user and application IDs and verifies
     * the response to ensure the activation is successfully initialized. It sets the activation
     * ID in the test configuration and asserts that the activation status is 'CREATED'.
     *
     * @param powerAuthClient the PowerAuthClient to perform activation operations
     * @throws Exception if any error occurs during activation initialization or verification
     */
    protected void initActivation(final PowerAuthClient powerAuthClient) throws Exception {
        final InitActivationRequest initActivationRequest = new InitActivationRequest();
        initActivationRequest.setUserId(USER_ID);
        initActivationRequest.setApplicationId(getApplicationId());

        final InitActivationResponse initActivationResponse = powerAuthClient.initActivation(initActivationRequest);
        assertNotNull(initActivationResponse);
        assertNotNull(initActivationResponse.getActivationId());
        assertNotNull(initActivationResponse.getActivationSignature());
        assertNotNull(initActivationResponse.getApplicationId());
        assertEquals(USER_ID, initActivationResponse.getUserId());
        assertEquals(getApplicationId(), initActivationResponse.getApplicationId());

        final GetActivationStatusResponse activationStatusResponse =
                powerAuthClient.getActivationStatus(initActivationResponse.getActivationId());

        assertEquals(ActivationStatus.CREATED, activationStatusResponse.getActivationStatus());
        setActivationId(activationStatusResponse.getActivationId());
        setActivationCode(activationStatusResponse.getActivationCode());
        setActivationName(activationStatusResponse.getActivationName());
    }

    /**
     * Creates an application in the PowerAuth Server if it does not already exist.
     * <p>
     * This method checks for the existence of an application and its version. If not present,
     * it creates them and sets relevant fields in the test configuration. It also ensures the
     * application version is supported and sets up activation recovery settings.
     *
     * @param powerAuthClient the PowerAuthClient to perform application-related operations
     * @throws Exception if any error occurs during application creation or setup
     */
    protected void createApplication(final PowerAuthClient powerAuthClient) throws Exception {
        final GetApplicationListResponse applicationsListResponse = powerAuthClient.getApplicationList();
        var applicationOptional = applicationsListResponse.getApplications().stream()
                .filter(app -> app.getApplicationId().equals(getApplicationName()))
                .findFirst();

        applicationOptional.ifPresent(app -> setApplicationId(app.getApplicationId()));
        boolean applicationExists = applicationOptional.isPresent();

        if (!applicationExists) {
            final CreateApplicationResponse response = powerAuthClient.createApplication(getApplicationName());
            assertNotEquals("0", response.getApplicationId());
            assertEquals(getApplicationName(), response.getApplicationId());
            setApplicationId(response.getApplicationId());
        }

        final GetApplicationDetailResponse detail = powerAuthClient.getApplicationDetail(getApplicationId());
        var versionOptional = detail.getVersions().stream()
                .filter(appVersion -> appVersion.getApplicationVersionId().equals(getApplicationVersion()))
                .findFirst();
        versionOptional.ifPresent(
                appVersion -> {
                    setApplicationVersionId(appVersion.getApplicationVersionId());
                    setApplicationKey(appVersion.getApplicationKey());
                    setApplicationSecret(appVersion.getApplicationSecret());
                });
        boolean versionExists = versionOptional.isPresent();

        setMasterPublicKey(detail.getMasterPublicKey());
        if (!versionExists) {
            final CreateApplicationVersionResponse versionResponse = powerAuthClient.createApplicationVersion(getApplicationId(), getApplicationVersion());
            assertNotEquals("0", versionResponse.getApplicationVersionId());
            assertEquals(getApplicationVersion(), versionResponse.getApplicationVersionId());
            setApplicationVersionId(versionResponse.getApplicationVersionId());
            setApplicationKey(versionResponse.getApplicationKey());
            setApplicationSecret(versionResponse.getApplicationSecret());
        } else {
            powerAuthClient.supportApplicationVersion(getApplicationId(), getApplicationVersionId());
        }
        final GetRecoveryConfigResponse recoveryResponse = powerAuthClient.getRecoveryConfig(getApplicationId());
        if (!recoveryResponse.isActivationRecoveryEnabled() || !recoveryResponse.isRecoveryPostcardEnabled() || recoveryResponse.getPostcardPublicKey() == null || recoveryResponse.getRemotePostcardPublicKey() == null) {
            final UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
            request.setApplicationId(getApplicationId());
            request.setActivationRecoveryEnabled(true);
            request.setRecoveryPostcardEnabled(true);
            request.setAllowMultipleRecoveryCodes(false);
            request.setRemotePostcardPublicKey(PUBLIC_KEY_RECOVERY_POSTCARD_BASE64);
            powerAuthClient.updateRecoveryConfig(request);
        }
    }

    /**
     * Creates a new callback URL in the PowerAuth Server and verifies its creation.
     * <p>
     * This method creates a callback URL with predefined settings and asserts the response
     * to ensure the callback URL is successfully created. It returns the response containing
     * the callback URL details.
     *
     * @param powerAuthClient the PowerAuthClient to create the callback URL
     * @return the response containing the created callback URL details
     * @throws Exception if any error occurs during callback URL creation
     */
    protected CreateCallbackUrlResponse createCallback(final PowerAuthClient powerAuthClient) throws Exception {
        final CreateCallbackUrlRequest callbackUrlRequest = createCallbackUrlRequest();
        final CreateCallbackUrlResponse response = powerAuthClient.createCallbackUrl(callbackUrlRequest);
        assertEquals(CALLBACK_NAME, response.getName());
        assertEquals(CALLBACK_URL, response.getCallbackUrl());
        assertEquals(getApplicationId(), response.getApplicationId());

        return response;
    }

    /**
     * Removes a specified callback URL from the PowerAuth Server.
     * <p>
     * This method deletes a callback URL using its ID and verifies the removal by asserting
     * the response.
     *
     * @param powerAuthClient the PowerAuthClient to remove the callback URL
     * @param callbackId      the ID of the callback URL to be removed
     * @throws Exception if any error occurs during callback URL removal
     */
    protected void removeCallback(final PowerAuthClient powerAuthClient, final String callbackId) throws Exception {
        final RemoveCallbackUrlRequest removeCallbackUrlRequest = new RemoveCallbackUrlRequest();
        removeCallbackUrlRequest.setId(callbackId);

        final RemoveCallbackUrlResponse removeCallbackUrlResponse = powerAuthClient.removeCallbackUrl(removeCallbackUrlRequest);
        assertEquals(callbackId, removeCallbackUrlResponse.getId());
        assertTrue(removeCallbackUrlResponse.isRemoved());
    }

    /**
     * Removes an activation from the PowerAuth Server.
     * <p>
     * This method deletes an activation using its ID and verifies the removal by asserting
     * the response.
     *
     * @param powerAuthClient the PowerAuthClient to remove the activation
     * @throws Exception if any error occurs during activation removal
     */
    protected void removeActivation(final PowerAuthClient powerAuthClient) throws Exception {
        final RemoveActivationRequest removeActivationRequest = new RemoveActivationRequest();
        removeActivationRequest.setActivationId(getActivationId());
        final RemoveActivationResponse removeActivationResponse = powerAuthClient.removeActivation(removeActivationRequest);
        assertTrue(removeActivationResponse.isRemoved());
    }

    /**
     * Creates a new operation in the PowerAuth Server.
     * <p>
     * This method creates an operation with predefined settings and asserts the response
     * to ensure the operation is successfully created. It returns the response containing
     * operation details.
     *
     * @param powerAuthClient the PowerAuthClient to create the operation
     * @return the response containing the created operation details
     * @throws Exception if any error occurs during operation creation
     */
    protected OperationDetailResponse createOperation(final PowerAuthClient powerAuthClient) throws Exception {
        final OperationDetailResponse operationDetailResponse = powerAuthClient
                .createOperation(createOperationCreateRequest(false));
        assertNotNull(operationDetailResponse.getId());
        assertEquals(OperationStatus.PENDING, operationDetailResponse.getStatus());
        assertEquals(getLoginOperationTemplateName(), operationDetailResponse.getTemplateName());
        return operationDetailResponse;
    }

    /**
     * Creates a new login operation template in the PowerAuth Server.
     * <p>
     * This method creates a login operation template with predefined settings. It sets the
     * template name and ID in the test configuration and asserts the response to ensure
     * the template is successfully created.
     *
     * @param powerAuthClient the PowerAuthClient to create the operation template
     * @throws Exception if any error occurs during operation template creation
     */
    protected void createLoginOperationTemplate(final PowerAuthClient powerAuthClient) throws Exception {
        final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
        request.setTemplateName(UUID.randomUUID().toString());
        request.setOperationType("login");
        request.getSignatureType().addAll(Arrays.asList(SignatureType.values()));
        request.setDataTemplate("A2");
        request.setExpiration(300L);
        request.setMaxFailureCount(5L);

        final OperationTemplateDetailResponse operationTemplate = powerAuthClient.createOperationTemplate(request);
        setLoginOperationTemplateName(operationTemplate.getTemplateName());
        setLoginOperationTemplateId(operationTemplate.getId());
    }

    /**
     * Converts a string representation of a master public key into its corresponding {@link PublicKey} object.
     * <p>
     * This method uses the {@link KeyConvertor} to decode the base64-encoded string representation of the master public key
     * into a byte array, which is then converted to a {@link PublicKey} object.
     *
     * @param keyConvertor The {@link KeyConvertor} used for converting the public key.
     * @return The {@link PublicKey} object corresponding to the decoded master public key.
     * @throws Exception if there is an error during the conversion process.
     */
    protected PublicKey wrapPublicKeyString(final KeyConvertor keyConvertor) throws Exception {
        return keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(getMasterPublicKey()));
    }

    /**
     * Generates an encrypted request for the Activation Layer 2 using ECIES (Elliptic Curve Integrated Encryption Scheme).
     * <p>
     * This method performs the following steps:
     * <ol>
     *   <li>Generates a new key pair and converts the public key to a byte array.</li>
     *   <li>Creates an {@link ActivationLayer2Request} with the activation name and device public key.</li>
     *   <li>Initializes a {@link ClientEncryptor} for Activation Layer 2 encryption.</li>
     *   <li>Serializes the {@link ActivationLayer2Request} into a byte array.</li>
     *   <li>Encrypts the serialized request data using the client encryptor.</li>
     * </ol>
     * </p>
     * The method returns an {@link EncryptedRequest} containing the encrypted request data and additional encryption parameters.
     *
     * @param keyGenerator     The {@link KeyGenerator} to generate the key pair.
     * @param keyConvertor     The {@link KeyConvertor} to convert the public key to a byte array.
     * @param objectMapper     The {@link ObjectMapper} to serialize the request.
     * @param encryptorFactory The factory to create a {@link ClientEncryptor}.
     * @param activationName   The activation name for the request.
     * @return The {@link EncryptedRequest} containing the encrypted request data.
     * @throws Exception if there is an error during the encryption or serialization process.
     */
    protected EncryptedRequest generateEncryptedRequestActivationLayer(final KeyGenerator keyGenerator,
                                                                       final KeyConvertor keyConvertor,
                                                                       final ObjectMapper objectMapper,
                                                                       final EncryptorFactory encryptorFactory,
                                                                       final String activationName) throws Exception {
        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final PublicKey publicKey = keyPair.getPublic();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));

        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(PowerAuthControllerTestConfig.PROTOCOL_VERSION, getApplicationKey(), null),
                new ClientEncryptorSecrets(wrapPublicKeyString(keyConvertor), getApplicationSecret())
        );

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        objectMapper.writeValue(baos, requestL2);
        return clientEncryptor.encryptRequest(baos.toByteArray());
    }

}
