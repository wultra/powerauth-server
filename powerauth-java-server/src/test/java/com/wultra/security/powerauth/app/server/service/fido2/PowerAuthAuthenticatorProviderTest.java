/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.fido2;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.AuditingServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.crypto.v4.KeyPairGenerationService;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.response.GetActivationListForUserResponse;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.json.JsonMapper;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test for {@link PowerAuthAuthenticatorProvider}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class PowerAuthAuthenticatorProviderTest {

    private static final String APPLICATION_ID = "app-1";
    private static final String USER_ID = "user-1";
    private static final String CREDENTIAL_ID = "credential-1";
    private static final byte[] DEVICE_PUBLIC_KEY = {1, 2, 3, 4, 5, 6, 7, 8};

    @Mock
    private ApplicationRepository applicationRepository;

    @Mock
    private ActivationServiceBehavior activations;

    private PowerAuthAuthenticatorProvider tested;

    @BeforeEach
    void setUp() {
        tested = new PowerAuthAuthenticatorProvider(
                applicationRepository,
                activations,
                mock(ActivationHistoryServiceBehavior.class),
                mock(CallbackUrlBehavior.class),
                mock(AuditingServiceBehavior.class),
                mock(ActivationQueryService.class),
                mock(CryptographyServiceFactory.class),
                mock(KeyPairGenerationService.class),
                mock(LocalizationProvider.class),
                JsonMapper.builder().build());
    }

    @Test
    void findByUserIdDoesNotRequestDevicePublicKeys() throws Exception {
        when(applicationRepository.findById(APPLICATION_ID)).thenReturn(Optional.of(application()));
        final GetActivationListForUserResponse firstPage = new GetActivationListForUserResponse();
        firstPage.getActivations().add(fido2Activation());
        when(activations.getActivationList(any())).thenReturn(firstPage, new GetActivationListForUserResponse());

        final List<AuthenticatorDetail> result = tested.findByUserId(USER_ID, APPLICATION_ID);

        final ArgumentCaptor<GetActivationListForUserRequest> captor = ArgumentCaptor.forClass(GetActivationListForUserRequest.class);
        verify(activations, times(2)).getActivationList(captor.capture());
        assertThat(captor.getAllValues()).noneMatch(GetActivationListForUserRequest::isIncludeDevicePublicKeys);
        assertThat(result).singleElement().satisfies(authenticator -> assertThat(authenticator.getPublicKeyBytes()).isEqualTo(DEVICE_PUBLIC_KEY));
    }

    @Test
    void findByCredentialIdUsesDevicePublicKeyBase64() throws Exception {
        when(applicationRepository.findById(APPLICATION_ID)).thenReturn(Optional.of(application()));
        when(activations.findByExternalId(APPLICATION_ID, CREDENTIAL_ID)).thenReturn(List.of(fido2Activation()));

        final Optional<AuthenticatorDetail> result = tested.findByCredentialId(CREDENTIAL_ID, APPLICATION_ID);

        assertThat(result).hasValueSatisfying(authenticator -> {
            assertThat(authenticator.getPublicKeyBytes()).isEqualTo(DEVICE_PUBLIC_KEY);
            assertThat(authenticator.getCredentialId()).isEqualTo(CREDENTIAL_ID);
        });
    }

    @Test
    void findByCredentialIdAndUserIdUsesDevicePublicKeyBase64() throws Exception {
        when(applicationRepository.findById(APPLICATION_ID)).thenReturn(Optional.of(application()));
        when(activations.findByUserIdAndExternalId(USER_ID, CREDENTIAL_ID)).thenReturn(List.of(fido2Activation()));

        final Optional<AuthenticatorDetail> result = tested.findByCredentialIdAndUserId(CREDENTIAL_ID, USER_ID);

        assertThat(result).hasValueSatisfying(authenticator -> assertThat(authenticator.getPublicKeyBytes()).isEqualTo(DEVICE_PUBLIC_KEY));
    }

    @Test
    void findByCredentialIdWithoutDevicePublicKeyHasNoPublicKeyBytes() throws Exception {
        when(applicationRepository.findById(APPLICATION_ID)).thenReturn(Optional.of(application()));
        final Activation activation = fido2Activation();
        activation.setDevicePublicKeyBase64(null);
        when(activations.findByExternalId(APPLICATION_ID, CREDENTIAL_ID)).thenReturn(List.of(activation));

        final Optional<AuthenticatorDetail> result = tested.findByCredentialId(CREDENTIAL_ID, APPLICATION_ID);

        assertThat(result).hasValueSatisfying(authenticator -> assertThat(authenticator.getPublicKeyBytes()).isNull());
    }

    private static ApplicationEntity application() {
        final ApplicationEntity application = new ApplicationEntity();
        application.setId(APPLICATION_ID);
        return application;
    }

    private static Activation fido2Activation() {
        final Activation activation = new Activation();
        activation.setActivationId("activation-1");
        activation.setApplicationId(APPLICATION_ID);
        activation.setUserId(USER_ID);
        activation.setExternalId(CREDENTIAL_ID);
        activation.setProtocol(ActivationProtocol.FIDO2);
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setDevicePublicKeyBase64(Base64.getEncoder().encodeToString(DEVICE_PUBLIC_KEY));
        return activation;
    }

}
