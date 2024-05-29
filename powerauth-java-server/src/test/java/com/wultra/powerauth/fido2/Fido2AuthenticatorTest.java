/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
 *
 */

package com.wultra.powerauth.fido2;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.authenticator.webauthn.SelfAttestedPackedAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.service.AssertionService;
import com.wultra.powerauth.fido2.service.RegistrationService;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorParameters;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import com.wultra.security.powerauth.fido2.model.request.AssertionVerificationRequest;
import com.wultra.security.powerauth.fido2.model.request.RegistrationRequest;
import com.wultra.security.powerauth.fido2.model.response.AssertionChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.AssertionVerificationResponse;
import com.wultra.security.powerauth.fido2.model.response.RegistrationChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.RegistrationResponse;
import io.getlime.security.powerauth.app.server.Application;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OperationTemplateServiceBehavior;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static com.wultra.powerauth.fido2.rest.model.enumeration.Fido2ConfigKeys.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test of self-attested packed authenticator against PowerAuth server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest(classes = Application.class)
@ActiveProfiles("test")
@Transactional
class Fido2AuthenticatorTest {

    private static final String RP_ID = "powerauth.com";
    private static final Origin ORIGIN = new Origin("http://localhost");
    private static final String USER_ID = "test_" + UUID.randomUUID();
    private static final String APPLICATION_ID = "fido2_test_" + UUID.randomUUID();
    private static final String ACTIVATION_NAME = "fido2_test_activation";
    private static final long REQUEST_TIMEOUT = 100L;
    
    private static final String TEST_ROOT_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBgTCCAScCEA0YfqmbKSw+gKpVgNSciIswCgYIKoZIzj0EAwIwRDESMBAGA1UE\n" +
            "CgwJU2hhcnBMYWIuMS4wLAYDVQQDDCVzcHJpbmctc2VjdXJpdHktd2ViYXV0aG4g\n" +
            "dGVzdCByb290IENBMCAXDTE3MDkyMjAzMTgyOVoYDzIxMTcwODI5MDMxODI5WjBE\n" +
            "MRIwEAYDVQQKDAlTaGFycExhYi4xLjAsBgNVBAMMJXNwcmluZy1zZWN1cml0eS13\n" +
            "ZWJhdXRobiB0ZXN0IHJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATN\n" +
            "dy65xbpUNeEzQcq1CgF6yGpGw8eUD3+Udlv5yjjraC26D+ZViUqYKPrBOnWNFxk5\n" +
            "F7zpHlZlRowzQUCE3f8iMAoGCCqGSM49BAMCA0gAMEUCIDaeeaAE6oDfMoZNwgFL\n" +
            "AcsJepkapCIreZrHLVnc8jWfAiEApZazduIuvFDp5k14YaiHJVZGsbuEbQ/qt/zz\n" +
            "jt6KouI=\n" +
            "-----END CERTIFICATE-----\n";

    private final ClientPlatform CLIENT_PLATFORM_SELF_ATTESTED = new ClientPlatform(ORIGIN, new WebAuthnAuthenticatorAdaptor(new SelfAttestedPackedAuthenticator()));
    private final ClientPlatform CLIENT_PLATFORM_BASIC_ATTESTATION = new ClientPlatform(ORIGIN, new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR));
    private final ClientPlatform CLIENT_PLATFORM_ANDROID_SAFETY_NET_ATTESTATION = new ClientPlatform(ORIGIN, new WebAuthnAuthenticatorAdaptor(EmulatorUtil.ANDROID_SAFETY_NET_AUTHENTICATOR));

    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final ApplicationConfigServiceBehavior applicationConfigService;
    private final OperationTemplateServiceBehavior operationTemplateService;
    private final RegistrationService registrationService;
    private final AssertionService assertionService;
    @Autowired private ActivationServiceBehavior activationServiceBehavior;


    @Autowired
    public Fido2AuthenticatorTest(ApplicationServiceBehavior applicationServiceBehavior, ApplicationConfigServiceBehavior applicationConfigService, OperationTemplateServiceBehavior operationTemplateService, RegistrationService registrationService, AssertionService assertionService) throws Exception {
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.applicationConfigService = applicationConfigService;
        this.operationTemplateService = operationTemplateService;
        this.registrationService = registrationService;
        this.assertionService = assertionService;
        createApplication();
        createOperationTemplate();
    }

    @Test
    void packedAuthenticatorSuccessTest() throws Exception {
        registerCredential();
        authenticate();
    }

    @Test
    void packedAuthenticatorInvalidRegistrationChallengeTest() throws Exception {
        // Use invalid challenge
        final Challenge challenge = new DefaultChallenge(Base64.getEncoder().encode(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)));
        final AuthenticatorSelectionCriteria authenticatorCriteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM, true, UserVerificationRequirement.REQUIRED);
        final PublicKeyCredentialParameters pkParam = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        final PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(USER_ID.getBytes(StandardCharsets.UTF_8), USER_ID, USER_ID);
        final PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(new PublicKeyCredentialRpEntity(RP_ID, RP_ID),
                user, challenge, Collections.singletonList(pkParam), REQUEST_TIMEOUT, Collections.emptyList(),
                authenticatorCriteria, AttestationConveyancePreference.DIRECT, null
        );

        // Prepare registration request
        final RegistrationRequest registrationRequest = prepareRegistrationRequest(credentialCreationOptions, challenge, CLIENT_PLATFORM_SELF_ATTESTED);

        // Register credential
        assertThrows(Fido2AuthenticationFailedException.class, () -> registrationService.register(registrationRequest));
    }

    @Test
    void packedAuthenticatorInvalidAttestationTest() throws Exception {
        // Obtain challenge from PowerAuth server
        final RegistrationChallengeResponse challengeResponse = registrationService.requestRegistrationChallenge(USER_ID, APPLICATION_ID);
        assertEquals(APPLICATION_ID, challengeResponse.getApplicationId());
        assertEquals(USER_ID, challengeResponse.getUserId());
        assertNotNull(challengeResponse.getChallenge());
        assertNotNull(challengeResponse.getActivationId());

        // Use obtained activation code as a challenge, prepare credential options
        final Challenge challenge = new DefaultChallenge(challengeResponse.getChallenge().getBytes(StandardCharsets.UTF_8));
        final AuthenticatorSelectionCriteria authenticatorCriteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM, true, UserVerificationRequirement.REQUIRED);
        final PublicKeyCredentialParameters pkParam = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        final PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(USER_ID.getBytes(StandardCharsets.UTF_8), USER_ID, USER_ID);
        final PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(new PublicKeyCredentialRpEntity(RP_ID, RP_ID),
                user, challenge, Collections.singletonList(pkParam), REQUEST_TIMEOUT, Collections.emptyList(),
                authenticatorCriteria, AttestationConveyancePreference.DIRECT, null
        );

        // Prepare registration request
        final RegistrationRequest registrationRequest = prepareRegistrationRequest(credentialCreationOptions, challenge, CLIENT_PLATFORM_ANDROID_SAFETY_NET_ATTESTATION);

        // Register credential
        assertThrows(Fido2AuthenticationFailedException.class, () -> registrationService.register(registrationRequest));
    }

    @Test
    void packedAuthenticatorNoAttestationTest() throws Exception {
        // Obtain challenge from PowerAuth server
        final RegistrationChallengeResponse challengeResponse = registrationService.requestRegistrationChallenge(USER_ID, APPLICATION_ID);
        assertEquals(APPLICATION_ID, challengeResponse.getApplicationId());
        assertEquals(USER_ID, challengeResponse.getUserId());
        assertNotNull(challengeResponse.getChallenge());
        assertNotNull(challengeResponse.getActivationId());

        // Use obtained activation code as a challenge, prepare credential options
        final Challenge challenge = new DefaultChallenge(challengeResponse.getChallenge().getBytes(StandardCharsets.UTF_8));
        final AuthenticatorSelectionCriteria authenticatorCriteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM, true, UserVerificationRequirement.REQUIRED);
        final PublicKeyCredentialParameters pkParam = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        final PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(USER_ID.getBytes(StandardCharsets.UTF_8), USER_ID, USER_ID);
        final PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(new PublicKeyCredentialRpEntity(RP_ID, RP_ID),
                user, challenge, Collections.singletonList(pkParam), REQUEST_TIMEOUT, Collections.emptyList(),
                authenticatorCriteria, AttestationConveyancePreference.NONE, null
        );

        // Prepare registration request
        final RegistrationRequest registrationRequest = prepareRegistrationRequest(credentialCreationOptions, challenge, CLIENT_PLATFORM_BASIC_ATTESTATION);

        // Register credential
        final RegistrationResponse registrationResponse = registrationService.register(registrationRequest);
        assertEquals(challengeResponse.getActivationId(), registrationResponse.getActivationId());
    }

    @Test
    void packedAuthenticatorInvalidAssertionChallengeTest() throws Exception {
        registerCredential();

        final Challenge challenge = new DefaultChallenge(Base64.getEncoder().encode(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)));
        final PublicKeyCredentialRequestOptions getOptions = new PublicKeyCredentialRequestOptions(challenge, REQUEST_TIMEOUT,
                RP_ID, null, UserVerificationRequirement.REQUIRED, null);
        final PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = CLIENT_PLATFORM_SELF_ATTESTED.get(getOptions);
        final AssertionVerificationRequest authRequest = new AssertionVerificationRequest();
        authRequest.setCredentialId(credential.getId());
        authRequest.setType(credential.getType());
        authRequest.setAuthenticatorAttachment(AuthenticatorAttachment.PLATFORM.getValue());
        authRequest.setApplicationId(APPLICATION_ID);
        authRequest.setRelyingPartyId(RP_ID);
        authRequest.setAllowedOrigins(Collections.singletonList(ORIGIN.toString()));
        authRequest.setRequiresUserVerification(true);
        authRequest.setExpectedChallenge(Base64.getEncoder().encodeToString(challenge.getValue()));

        // Convert clientDataJSON and authenticatorData into object and supply encoded values for signature verification
        final String clientDataJSON = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getClientDataJSON());
        final String authenticatorData = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getAuthenticatorData());
        final byte[] userHandle = Objects.requireNonNull(credential.getResponse()).getUserHandle();
        final byte[] signature = Objects.requireNonNull(credential.getResponse()).getSignature();

        final com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse assertionResponse = new com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse();
        assertionResponse.setClientDataJSON(clientDataJSON);
        assertionResponse.setAuthenticatorData(authenticatorData);
        assertionResponse.setUserHandle(new String(userHandle, StandardCharsets.UTF_8));
        assertionResponse.setSignature(signature);
        authRequest.setResponse(assertionResponse);

        // Authenticate
        assertThrows(Fido2AuthenticationFailedException.class, () -> assertionService.authenticate(authRequest));
    }

    @Test
    void packedAuthenticatorInvalidSignatureTest() throws Exception {
        registerCredential();

        // Obtain authentication challenge from PowerAuth server
        final AssertionChallengeRequest challengeRequest = new AssertionChallengeRequest();
        challengeRequest.setApplicationIds(Collections.singletonList(APPLICATION_ID));
        challengeRequest.setTemplateName("login");
        challengeRequest.setExternalId(UUID.randomUUID().toString());
        final AssertionChallengeResponse challengeResponse = assertionService.requestAssertionChallenge(challengeRequest);
        assertEquals(APPLICATION_ID, challengeResponse.getApplicationIds().get(0));
        assertNull(challengeResponse.getUserId());
        assertNotNull(challengeResponse.getChallenge());
        assertEquals(0, challengeResponse.getFailedAttempts());
        assertEquals(5, challengeResponse.getMaxFailedAttempts());

        // Prepare authentication request
        final Challenge challenge = new DefaultChallenge(challengeResponse.getChallenge().getBytes(StandardCharsets.UTF_8));
        final PublicKeyCredentialRequestOptions getOptions = new PublicKeyCredentialRequestOptions(challenge, REQUEST_TIMEOUT,
                RP_ID, null, UserVerificationRequirement.REQUIRED, null);
        final PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = CLIENT_PLATFORM_SELF_ATTESTED.get(getOptions);
        final AssertionVerificationRequest authRequest = new AssertionVerificationRequest();
        authRequest.setCredentialId(credential.getId());
        authRequest.setType(credential.getType());
        authRequest.setAuthenticatorAttachment(AuthenticatorAttachment.PLATFORM.getValue());
        authRequest.setApplicationId(APPLICATION_ID);
        authRequest.setRelyingPartyId(RP_ID);
        authRequest.setAllowedOrigins(Collections.singletonList(ORIGIN.toString()));
        authRequest.setRequiresUserVerification(true);
        authRequest.setExpectedChallenge(new String(challenge.getValue(), StandardCharsets.UTF_8));

        // Convert clientDataJSON and authenticatorData into object and supply encoded values for signature verification
        final String clientDataJSON = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getClientDataJSON());
        final String authenticatorData = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getAuthenticatorData());
        final byte[] userHandle = Objects.requireNonNull(credential.getResponse()).getUserHandle();

        final com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse assertionResponse = new com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse();
        assertionResponse.setClientDataJSON(clientDataJSON);
        assertionResponse.setAuthenticatorData(authenticatorData);
        assertionResponse.setUserHandle(new String(userHandle, StandardCharsets.UTF_8));
        assertionResponse.setSignature(new byte[32]);
        authRequest.setResponse(assertionResponse);

        // Authenticate
        assertThrows(Fido2AuthenticationFailedException.class, () -> assertionService.authenticate(authRequest));
    }

    @Test
    void packedAuthenticatorUnsupportedAaguidTest() throws Exception {
        // Configure server not to allow any AAGUIDs
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ALLOWED_AAGUIDS);
        requestCreate.setValues(Collections.emptyList());
        applicationConfigService.createApplicationConfig(requestCreate);

        // Registration should fail
        assertThrows(Fido2AuthenticationFailedException.class, this::registerCredential);

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ALLOWED_AAGUIDS);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    @Test
    void packedAuthenticatorInvalidAaguidTest() throws Exception {
        // Configure server not to allow only one AAGUID which differs from registration request AAGUID
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ALLOWED_AAGUIDS);
        requestCreate.setValues(List.of("00000000-0000-0000-0000-000000000001"));
        applicationConfigService.createApplicationConfig(requestCreate);

        // Registration should fail
        assertThrows(Fido2AuthenticationFailedException.class, this::registerCredential);

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ALLOWED_AAGUIDS);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    @Test
    void packedAuthenticatorValidAaguidTest() throws Exception {
        // Configure server not to allow valid AAGUID only
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ALLOWED_AAGUIDS);
        requestCreate.setValues(List.of("00000000-0000-0000-0000-000000000000"));
        applicationConfigService.createApplicationConfig(requestCreate);

        // Registration should succeed
        registerCredential();

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ALLOWED_AAGUIDS);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    @Test
    void packedAuthenticatorUnsupportedAttestationFormatTest() throws Exception {
        // Configure server not to allow any attestation formats
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ALLOWED_ATTESTATION_FMT);
        requestCreate.setValues(Collections.emptyList());
        applicationConfigService.createApplicationConfig(requestCreate);

        // Registration should fail
        assertThrows(Fido2AuthenticationFailedException.class, this::registerCredential);

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ALLOWED_ATTESTATION_FMT);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    @Test
    void packedAuthenticatorInvalidAttestationFormatTest() throws Exception {
        // Configure server not to allow only an attestation format which differs from request attestation format
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ALLOWED_ATTESTATION_FMT);
        requestCreate.setValues(List.of("none"));
        applicationConfigService.createApplicationConfig(requestCreate);

        // Registration should fail
        assertThrows(Fido2AuthenticationFailedException.class, this::registerCredential);

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ALLOWED_ATTESTATION_FMT);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    @Test
    void packedAuthenticatorValidAttestationFormatTest() throws Exception {
        // Configure server not to allow only an attestation format which matches request attestation format
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ALLOWED_ATTESTATION_FMT);
        requestCreate.setValues(List.of("packed"));
        applicationConfigService.createApplicationConfig(requestCreate);

        // Registration should succeed
        registerCredential();

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ALLOWED_ATTESTATION_FMT);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    @Test
    void packedAuthenticatorBasicAttestationTest() throws Exception {
        // Obtain challenge from PowerAuth server
        final RegistrationChallengeResponse challengeResponse = registrationService.requestRegistrationChallenge(USER_ID, APPLICATION_ID);
        assertEquals(APPLICATION_ID, challengeResponse.getApplicationId());
        assertEquals(USER_ID, challengeResponse.getUserId());
        assertNotNull(challengeResponse.getChallenge());
        assertNotNull(challengeResponse.getActivationId());

        final Challenge challenge = new DefaultChallenge(challengeResponse.getChallenge().getBytes(StandardCharsets.UTF_8));
        final AuthenticatorSelectionCriteria authenticatorCriteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM, true, UserVerificationRequirement.REQUIRED);
        final PublicKeyCredentialParameters pkParam = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        final PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(USER_ID.getBytes(StandardCharsets.UTF_8), USER_ID, USER_ID);
        final PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(new PublicKeyCredentialRpEntity(RP_ID, RP_ID),
                user, challenge, Collections.singletonList(pkParam), REQUEST_TIMEOUT, Collections.emptyList(),
                authenticatorCriteria, AttestationConveyancePreference.DIRECT, null
        );

        // Configure root certificate on server
        final CreateApplicationConfigRequest requestCreate = new CreateApplicationConfigRequest();
        requestCreate.setApplicationId(APPLICATION_ID);
        requestCreate.setKey(CONFIG_KEY_ROOT_CA_CERTS);
        requestCreate.setValues(List.of(TEST_ROOT_CERT));
        applicationConfigService.createApplicationConfig(requestCreate);

        // Prepare registration request
        final RegistrationRequest registrationRequest = prepareRegistrationRequest(credentialCreationOptions, challenge, CLIENT_PLATFORM_BASIC_ATTESTATION);

        // Register credential
        final RegistrationResponse registrationResponse = registrationService.register(registrationRequest);
        assertEquals(APPLICATION_ID, registrationResponse.getApplicationId());

        // Check that activation is in ACTIVE state
        final GetActivationStatusRequest activationStatusRequest2 = new GetActivationStatusRequest();
        activationStatusRequest2.setActivationId(challengeResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, activationServiceBehavior.getActivationStatus(activationStatusRequest2).getActivationStatus());

        // Remove configuration
        final RemoveApplicationConfigRequest requestRemove = new RemoveApplicationConfigRequest();
        requestRemove.setApplicationId(APPLICATION_ID);
        requestRemove.setKey(CONFIG_KEY_ROOT_CA_CERTS);
        applicationConfigService.removeApplicationConfig(requestRemove);
    }

    private void createApplication() throws Exception {
        // Search if application for FIDO2 tests exists
        final boolean applicationFound = applicationServiceBehavior.getApplicationList().getApplications().stream()
                .map(com.wultra.security.powerauth.client.model.entity.Application::getApplicationId)
                .anyMatch(APPLICATION_ID::equals);
        if (applicationFound) {
            return;
        }
        // Create application for FIDO2 tests
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId(APPLICATION_ID);
        applicationServiceBehavior.createApplication(request);
    }

    private void registerCredential() throws Exception {
        // Obtain challenge from PowerAuth server
        final RegistrationChallengeResponse challengeResponse = registrationService.requestRegistrationChallenge(USER_ID, APPLICATION_ID);
        assertEquals(APPLICATION_ID, challengeResponse.getApplicationId());
        assertEquals(USER_ID, challengeResponse.getUserId());
        assertNotNull(challengeResponse.getChallenge());
        assertNotNull(challengeResponse.getActivationId());

        // Check that activation is in CREATED state
        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(challengeResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, activationServiceBehavior.getActivationStatus(activationStatusRequest).getActivationStatus());

        // Use obtained activation code as a challenge, prepare credential options
        final Challenge challenge = new DefaultChallenge(challengeResponse.getChallenge().getBytes(StandardCharsets.UTF_8));
        final AuthenticatorSelectionCriteria authenticatorCriteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM, true, UserVerificationRequirement.REQUIRED);
        final PublicKeyCredentialParameters pkParam = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        final PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(USER_ID.getBytes(StandardCharsets.UTF_8), USER_ID, USER_ID);
        final PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(new PublicKeyCredentialRpEntity(RP_ID, RP_ID),
                user, challenge, Collections.singletonList(pkParam), REQUEST_TIMEOUT, Collections.emptyList(),
                authenticatorCriteria, AttestationConveyancePreference.DIRECT, null
        );

        // Prepare registration request
        final RegistrationRequest registrationRequest = prepareRegistrationRequest(credentialCreationOptions, challenge, CLIENT_PLATFORM_SELF_ATTESTED);

        // Register credential
        final RegistrationResponse registrationResponse = registrationService.register(registrationRequest);
        assertEquals(APPLICATION_ID, registrationResponse.getApplicationId());

        // Check that activation is in ACTIVE state
        final GetActivationStatusRequest activationStatusRequest2 = new GetActivationStatusRequest();
        activationStatusRequest2.setActivationId(challengeResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, activationServiceBehavior.getActivationStatus(activationStatusRequest2).getActivationStatus());
    }

    private RegistrationRequest prepareRegistrationRequest(PublicKeyCredentialCreationOptions credentialCreationOptions, Challenge challenge, ClientPlatform clientPlatform) throws Exception {
        // Create credential on authenticator emulator
        final PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
        final RegistrationRequest registrationRequest = new RegistrationRequest();
        registrationRequest.setApplicationId(APPLICATION_ID);
        registrationRequest.setActivationName(ACTIVATION_NAME);
        registrationRequest.setExpectedChallenge(new String(challenge.getValue(), StandardCharsets.UTF_8));
        final AuthenticatorParameters authenticationParameters = new AuthenticatorParameters();
        authenticationParameters.setCredentialId(credential.getId());
        authenticationParameters.setRelyingPartyId(RP_ID);
        authenticationParameters.setAllowedOrigins(Collections.singletonList(ORIGIN.toString()));
        authenticationParameters.setType(credential.getType());
        authenticationParameters.setRequiresUserVerification(true);

        // Convert clientDataJSON and attestationObject into object and supply encoded values for signature verification
        final String clientDataJSON = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getClientDataJSON());
        final String attestationObject = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getAttestationObject());

        final com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAttestationResponse attestationResponse = new com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAttestationResponse();
        attestationResponse.setClientDataJSON(clientDataJSON);
        attestationResponse.setAttestationObject(attestationObject);
        final AuthenticatorTransport[] transports = credential.getResponse().getTransports().toArray(new AuthenticatorTransport[0]);
        attestationResponse.setTransports(Arrays.stream(transports).map(AuthenticatorTransport::toString).collect(Collectors.toList()));
        authenticationParameters.setResponse(attestationResponse);
        registrationRequest.setAuthenticatorParameters(authenticationParameters);
        return registrationRequest;
    }

    private void createOperationTemplate() throws Exception {
        final boolean templateFound = operationTemplateService.getAllTemplates().stream()
                .map(OperationTemplateDetailResponse::getTemplateName)
                .anyMatch("login"::equals);
        if (templateFound) {
            return;
        }
        final OperationTemplateCreateRequest templateCreateRequest = new OperationTemplateCreateRequest();
        templateCreateRequest.setTemplateName("login");
        templateCreateRequest.setOperationType("login");
        templateCreateRequest.setDataTemplate("A2");
        templateCreateRequest.setMaxFailureCount(5L);
        templateCreateRequest.setExpiration(300L);
        templateCreateRequest.getSignatureType().add(SignatureType.POSSESSION_KNOWLEDGE);
        operationTemplateService.createOperationTemplate(templateCreateRequest);
    }

    private void authenticate() throws Exception {
        // Obtain authentication challenge from PowerAuth server
        final AssertionChallengeRequest challengeRequest = new AssertionChallengeRequest();
        challengeRequest.setApplicationIds(Collections.singletonList(APPLICATION_ID));
        challengeRequest.setTemplateName("login");
        challengeRequest.setExternalId(UUID.randomUUID().toString());
        final AssertionChallengeResponse challengeResponse = assertionService.requestAssertionChallenge(challengeRequest);
        assertEquals(APPLICATION_ID, challengeResponse.getApplicationIds().get(0));
        assertNull(challengeResponse.getUserId());
        assertNotNull(challengeResponse.getChallenge());
        assertEquals(0, challengeResponse.getFailedAttempts());
        assertEquals(5, challengeResponse.getMaxFailedAttempts());

        // Prepare authentication request
        final Challenge challenge = new DefaultChallenge(challengeResponse.getChallenge().getBytes(StandardCharsets.UTF_8));
        final PublicKeyCredentialRequestOptions getOptions = new PublicKeyCredentialRequestOptions(challenge, REQUEST_TIMEOUT,
                RP_ID, null, UserVerificationRequirement.REQUIRED, null);
        final PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = CLIENT_PLATFORM_SELF_ATTESTED.get(getOptions);
        final AssertionVerificationRequest authRequest = new AssertionVerificationRequest();
        authRequest.setCredentialId(credential.getId());
        authRequest.setType(credential.getType());
        authRequest.setAuthenticatorAttachment(AuthenticatorAttachment.PLATFORM.getValue());
        authRequest.setApplicationId(APPLICATION_ID);
        authRequest.setRelyingPartyId(RP_ID);
        authRequest.setAllowedOrigins(Collections.singletonList(ORIGIN.toString()));
        authRequest.setRequiresUserVerification(true);
        authRequest.setExpectedChallenge(new String(challenge.getValue(), StandardCharsets.UTF_8));

        // Convert clientDataJSON and authenticatorData into object and supply encoded values for signature verification
        final String clientDataJSON = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getClientDataJSON());
        final String authenticatorData = Base64.getEncoder().encodeToString(Objects.requireNonNull(credential.getResponse()).getAuthenticatorData());
        final byte[] userHandle = Objects.requireNonNull(credential.getResponse()).getUserHandle();
        final byte[] signature = Objects.requireNonNull(credential.getResponse()).getSignature();

        final com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse assertionResponse = new com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse();
        assertionResponse.setClientDataJSON(clientDataJSON);
        assertionResponse.setAuthenticatorData(authenticatorData);
        assertionResponse.setUserHandle(new String(userHandle, StandardCharsets.UTF_8));
        assertionResponse.setSignature(signature);
        authRequest.setResponse(assertionResponse);

        // Authenticate
        final AssertionVerificationResponse authResponse = assertionService.authenticate(authRequest);
        assertEquals(APPLICATION_ID, authResponse.getApplicationId());

    }

}
