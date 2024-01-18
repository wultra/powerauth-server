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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.Application;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Configuration
public class PowerAuthControllerTestConfig {

    private static final String POWERAUTH_REST_URL = "http://localhost:8080/rest";
    private static final String PUBLIC_KEY_RECOVERY_POSTCARD_BASE64 = "BABXgGoj4Lizl3GN0rjrtileEEwekFkpX1ERS9yyYjyuM1Iqdti3ihtATBxk5XGvjetPO1YC+qXciUYjIsETtbI=";
    protected static final String USER_ID = "test-user";
    protected static final String DATA = "A2";
    protected static final String CALLBACK_NAME = UUID.randomUUID().toString();
    protected static final String CALLBACK_URL = "http://test.test";

    private String applicationId;
    private String applicationVersionId;
    private String applicationKey;
    private String applicationSecret;
    private String masterPublicKey;
    private String applicationVersion = "default";
    private final String applicationName = "Pa_tests_component";
    private Long loginOperationTemplateId;
    private String loginOperationTemplateName;
    private String activationId;

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
     * @throws Exception if the operation creation request setup fails
     */
    private OperationCreateRequest createOperationCreateRequest(final boolean proximityOtpEnabled) throws Exception {
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
     * Tests and prepares the initialization and status verification of a new activation.
     * <p>
     * This test performs the following actions:
     * <ol>
     *   <li>Initializes a new activation using the provided user ID and application ID from the configuration.</li>
     *   <li>Verifies the response from the initialization to ensure that activation ID, activation signature, and application ID are not null.</li>
     *   <li>Asserts that the user ID in the response matches the provided user ID.</li>
     *   <li>Asserts that the application ID in the response matches the application ID from the configuration.</li>
     *   <li>Retrieves the activation status for the new activation and verifies that its status is 'CREATED'.</li>
     * </ol>
     * </p>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
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
    }

    protected void createApplication(final PowerAuthClient powerAuthClient) throws Exception {
        // Create application if it does not exist
        final GetApplicationListResponse applicationsListResponse = powerAuthClient.getApplicationList();
        boolean applicationExists = false;
        for (Application app : applicationsListResponse.getApplications()) {
            if (app.getApplicationId().equals(getApplicationName())) {
                applicationExists = true;
                setApplicationId(app.getApplicationId());
            }
        }
        if (!applicationExists) {
            final CreateApplicationResponse response = powerAuthClient.createApplication(getApplicationName());
            assertNotEquals("0", response.getApplicationId());
            assertEquals(getApplicationName(), response.getApplicationId());
            setApplicationId(response.getApplicationId());
        }

        // Create application version if it does not exist
        final GetApplicationDetailResponse detail = powerAuthClient.getApplicationDetail(getApplicationId());
        boolean versionExists = false;
        for (ApplicationVersion appVersion : detail.getVersions()) {
            if (appVersion.getApplicationVersionId().equals(getApplicationVersion())) {
                versionExists = true;
                setApplicationVersionId(appVersion.getApplicationVersionId());
                setApplicationKey(appVersion.getApplicationKey());
                setApplicationSecret(appVersion.getApplicationSecret());
            }
        }
        setMasterPublicKey(detail.getMasterPublicKey());
        if (!versionExists) {
            final CreateApplicationVersionResponse versionResponse = powerAuthClient.createApplicationVersion(getApplicationId(), getApplicationVersion());
            assertNotEquals("0", versionResponse.getApplicationVersionId());
            assertEquals(getApplicationVersion(), versionResponse.getApplicationVersionId());
            setApplicationVersionId(versionResponse.getApplicationVersionId());
            setApplicationKey(versionResponse.getApplicationKey());
            setApplicationSecret(versionResponse.getApplicationSecret());
        } else {
            // Make sure application version is supported
            powerAuthClient.supportApplicationVersion(getApplicationId(), getApplicationVersionId());
        }
        // Set up activation recovery
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

    protected CreateCallbackUrlResponse createCallback(final PowerAuthClient powerAuthClient) throws Exception {
        final CreateCallbackUrlRequest callbackUrlRequest = createCallbackUrlRequest();
        final CreateCallbackUrlResponse response = powerAuthClient.createCallbackUrl(callbackUrlRequest);
        assertEquals(CALLBACK_NAME, response.getName());
        assertEquals(CALLBACK_URL, response.getCallbackUrl());
        assertEquals(getApplicationId(), response.getApplicationId());

        return response;
    }

    protected void removeCallback(final PowerAuthClient powerAuthClient, final String callbackId) throws Exception {
        final RemoveCallbackUrlRequest removeCallbackUrlRequest = new RemoveCallbackUrlRequest();
        removeCallbackUrlRequest.setId(callbackId);

        final RemoveCallbackUrlResponse removeCallbackUrlResponse = powerAuthClient.removeCallbackUrl(removeCallbackUrlRequest);
        assertEquals(callbackId, removeCallbackUrlResponse.getId());
        assertTrue(removeCallbackUrlResponse.isRemoved());
    }

    protected void removeActivation(final PowerAuthClient powerAuthClient) throws Exception {
        final RemoveActivationRequest removeActivationRequest = new RemoveActivationRequest();
        removeActivationRequest.setActivationId(getActivationId());
        final RemoveActivationResponse removeActivationResponse = powerAuthClient.removeActivation(removeActivationRequest);
        assertTrue(removeActivationResponse.isRemoved());
    }

    protected OperationDetailResponse createOperation(final PowerAuthClient powerAuthClient) throws Exception {
        final OperationCreateRequest createRequest = createOperationCreateRequest(false);
        final OperationDetailResponse operationDetailResponse = powerAuthClient
                .createOperation(createOperationCreateRequest(false));
        assertNotNull(operationDetailResponse.getId());
        assertEquals(OperationStatus.PENDING, operationDetailResponse.getStatus());
        assertEquals(getLoginOperationTemplateName(), operationDetailResponse.getTemplateName());
        return operationDetailResponse;
    }

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


}
