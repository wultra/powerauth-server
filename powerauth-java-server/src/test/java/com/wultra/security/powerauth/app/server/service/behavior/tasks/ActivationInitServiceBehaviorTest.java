/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.AsymmetricSignatureService;
import com.wultra.security.powerauth.app.server.service.crypto.v4.KeyPairGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.security.Security;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ActivationInitServiceBehaviorTest {

    @Mock
    private ApplicationRepository applicationRepository;

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    @Mock
    private ActivationRepository activationRepository;

    @Mock
    private MasterKeyPairRepository masterKeyPairRepository;

    @Mock
    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    @Mock
    private CallbackUrlBehavior callbackUrlBehavior;

    @Mock
    private KeyPairGenerationService keyPairGenerationService;

    @Mock
    private AsymmetricSignatureService asymmetricSignatureService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private ActivationInitServiceBehavior behavior;

    @BeforeAll
    static void initBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void initActivation_shouldReturnPopulatedResponse_whenValidRequest() throws Exception {
        final InitActivationRequest request = request("app-1", "user-1");
        stubHappyPath("app-1");

        final InitActivationResponse response = behavior.initActivation(request);

        assertNotNull(response.getActivationId());
        assertNotNull(response.getActivationCode());
        assertEquals("user-1", response.getUserId());
        assertEquals("app-1", response.getApplicationId());
    }

    @Test
    void initActivation_shouldSetActivationSignature_whenSignatureComputed() throws Exception {
        final InitActivationRequest request = request("app-2", "user-2");
        stubHappyPath("app-2");
        when(asymmetricSignatureService.computeSignaturesForActivation(any()))
                .thenReturn(Map.of("ES256", "sig-value", "ES384", "sig-value-2"));

        final InitActivationResponse response = behavior.initActivation(request);

        assertEquals("sig-value", response.getActivationSignature());
        assertEquals(2, response.getActivationSignatures().size());
    }

    @Test
    void initActivation_shouldUseDefaultMaxFailureCount_whenNotSetInRequest() throws Exception {
        final InitActivationRequest request = request("app-3", "user-3");
        // maxFailureCount not set → null
        stubHappyPath("app-3");
        when(powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts()).thenReturn(5L);

        final ArgumentCaptor<com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity> captor =
                ArgumentCaptor.forClass(com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity.class);

        behavior.initActivation(request);

        verify(activationHistoryServiceBehavior).saveActivationAndLogChange(captor.capture());
        assertEquals(5L, captor.getValue().getMaxFailedAttempts());
    }

    @Test
    void initActivation_shouldUseCustomMaxFailureCount_whenPositiveValueProvided() throws Exception {
        final InitActivationRequest request = request("app-4", "user-4");
        request.setMaxFailureCount(3L);
        stubHappyPath("app-4");

        final ArgumentCaptor<com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity> captor =
                ArgumentCaptor.forClass(com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity.class);

        behavior.initActivation(request);

        verify(activationHistoryServiceBehavior).saveActivationAndLogChange(captor.capture());
        assertEquals(3L, captor.getValue().getMaxFailedAttempts());
    }

    @Test
    void initActivation_shouldUseProvidedExpirationTimestamp_whenSetInRequest() throws Exception {
        final Date expiration = new Date(System.currentTimeMillis() + 60_000L);
        final InitActivationRequest request = request("app-5", "user-5");
        request.setTimestampActivationExpire(expiration);
        stubHappyPath("app-5");

        final ArgumentCaptor<com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity> captor =
                ArgumentCaptor.forClass(com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity.class);

        behavior.initActivation(request);

        verify(activationHistoryServiceBehavior).saveActivationAndLogChange(captor.capture());
        assertEquals(expiration, captor.getValue().getTimestampActivationExpire());
    }

    @Test
    void initActivation_shouldAddFlagsToActivation_whenFlagsProvided() throws Exception {
        final InitActivationRequest request = request("app-6", "user-6");
        request.setFlags(List.of("FLAG_A", "FLAG_B"));
        stubHappyPath("app-6");

        final ArgumentCaptor<com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity> captor =
                ArgumentCaptor.forClass(com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity.class);

        behavior.initActivation(request);

        verify(activationHistoryServiceBehavior).saveActivationAndLogChange(captor.capture());
        assertTrue(captor.getValue().getFlags().containsAll(List.of("FLAG_A", "FLAG_B")));
    }

    @Test
    void initActivation_shouldNotifyCallbackListeners_whenActivationCreated() throws Exception {
        final InitActivationRequest request = request("app-7", "user-7");
        stubHappyPath("app-7");

        behavior.initActivation(request);

        verify(callbackUrlBehavior).notifyCallbackListenersOnActivationChange(any());
    }

    @Test
    void initActivation_shouldThrowInvalidApplication_whenApplicationNotFound() throws Exception {
        final InitActivationRequest request = request("missing-app", "user-x");
        when(applicationRepository.findById("missing-app")).thenReturn(Optional.empty());
        final GenericServiceException expected = new GenericServiceException(ServiceError.INVALID_APPLICATION, "not found");
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.INVALID_APPLICATION, ex.getCode());
    }

    @Test
    void initActivation_shouldThrowActivationCreateFailed_whenMaxFailureCountIsZero() throws Exception {
        final InitActivationRequest request = request("app-8", "user-8");
        request.setMaxFailureCount(0L);
        stubApplicationOnly("app-8");
        final GenericServiceException expected = new GenericServiceException(ServiceError.ACTIVATION_CREATE_FAILED, "invalid");
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_CREATE_FAILED)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.ACTIVATION_CREATE_FAILED, ex.getCode());
    }

    @Test
    void initActivation_shouldThrowActivationCreateFailed_whenMaxFailureCountIsNegative() throws Exception {
        final InitActivationRequest request = request("app-9", "user-9");
        request.setMaxFailureCount(-1L);
        stubApplicationOnly("app-9");
        final GenericServiceException expected = new GenericServiceException(ServiceError.ACTIVATION_CREATE_FAILED, "invalid");
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_CREATE_FAILED)).thenReturn(expected);

        assertThrows(GenericServiceException.class, () -> behavior.initActivation(request));
    }

    @Test
    void initActivation_shouldThrowUnableToGenerateActivationCode_whenActivationCodeConstraintViolationOccurs() throws Exception {
        final InitActivationRequest request = request("app-10", "user-10");
        stubHappyPath("app-10");
        doThrow(new DataIntegrityViolationException("Unique constraint violation: pa_activation_code_application_uk"))
                .when(activationHistoryServiceBehavior).saveActivationAndLogChange(any());
        final GenericServiceException expected = new GenericServiceException(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE, "collision");
        when(localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE, ex.getCode());
    }

    @Test
    void initActivation_shouldThrowNoMasterServerKeypair_whenMasterKeyPairMissing() throws Exception {
        final InitActivationRequest request = request("app-11", "user-11");
        stubApplicationOnly("app-11");
        when(powerAuthServiceConfiguration.getActivationValidityBeforeActive()).thenReturn(300_000);
        when(powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts()).thenReturn(5L);
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-11")).thenReturn(null);
        final GenericServiceException expected = new GenericServiceException(ServiceError.NO_MASTER_SERVER_KEYPAIR, "missing");
        when(localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.NO_MASTER_SERVER_KEYPAIR, ex.getCode());
        verify(activationHistoryServiceBehavior, never()).saveActivationAndLogChange(any());
    }

    @Test
    void initActivation_shouldThrowUnableToGenerateActivationCode_whenDataIntegrityViolationOccurs() throws Exception {
        final InitActivationRequest request = request("app-12", "user-12");
        stubHappyPath("app-12");
        doThrow(new DataIntegrityViolationException("PK or unique constraint violation"))
                .when(activationHistoryServiceBehavior).saveActivationAndLogChange(any());
        final GenericServiceException expected = new GenericServiceException(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE, "collision");
        when(localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE, ex.getCode());
    }

    @Test
    void initActivation_shouldThrowInvalidRequest_whenOtpValidationSetWithoutOtp() throws Exception {
        final InitActivationRequest request = request("app-13", "user-13");
        request.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
        // activationOtp not set → invalid
        stubApplicationOnly("app-13");
        when(powerAuthServiceConfiguration.getActivationValidityBeforeActive()).thenReturn(300_000);
        when(powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts()).thenReturn(5L);
        final GenericServiceException expected = new GenericServiceException(ServiceError.INVALID_REQUEST, "missing otp");
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.INVALID_REQUEST, ex.getCode());
    }

    @Test
    void initActivation_shouldThrowInvalidRequest_whenOtpValidationCombinedWithCommitPhase() throws Exception {
        final InitActivationRequest request = request("app-14", "user-14");
        request.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
        request.setActivationOtp("123456");
        request.setCommitPhase(CommitPhase.ON_KEY_EXCHANGE);
        stubApplicationOnly("app-14");
        when(powerAuthServiceConfiguration.getActivationValidityBeforeActive()).thenReturn(300_000);
        when(powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts()).thenReturn(5L);
        final GenericServiceException expected = new GenericServiceException(ServiceError.INVALID_REQUEST, "invalid combo");
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST)).thenReturn(expected);

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> behavior.initActivation(request));
        assertEquals(ServiceError.INVALID_REQUEST, ex.getCode());
    }

    // --- helpers ---

    private static InitActivationRequest request(String applicationId, String userId) {
        final InitActivationRequest request = new InitActivationRequest();
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setProtocol(ActivationProtocol.POWERAUTH);
        return request;
    }

    private void stubApplicationOnly(String applicationId) {
        final ApplicationEntity app = new ApplicationEntity();
        app.setId(applicationId);
        when(applicationRepository.findById(applicationId)).thenReturn(Optional.of(app));
    }

    private void stubHappyPath(String applicationId) throws Exception {
        stubApplicationOnly(applicationId);
        // lenient: not called when maxFailureCount is provided in request
        lenient().when(powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts()).thenReturn(5L);
        // lenient: not called when timestampActivationExpire is provided in request
        lenient().when(powerAuthServiceConfiguration.getActivationValidityBeforeActive()).thenReturn(300_000);
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(new MasterKeyPairEntity());
        // lenient: not called when save throws DataIntegrityViolationException
        lenient().when(asymmetricSignatureService.computeSignaturesForActivation(any()))
                .thenReturn(Map.of("ES256", "test-sig"));
    }
}
