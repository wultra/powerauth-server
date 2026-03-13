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

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.crypto.MasterKeyGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Security;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApplicationServiceBehaviorTest {

    @Mock
    private MasterKeyGenerationService masterKeyGenerationService;

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private ApplicationRepository applicationRepository;

    @Mock
    private ApplicationVersionRepository applicationVersionRepository;

    @InjectMocks
    private ApplicationServiceBehavior applicationServiceBehavior;

    @BeforeAll
    static void setUpBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void createApplication_shouldReturnResponseWithApplicationId_whenSucceeds() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("test-app");

        final ApplicationEntity savedApplication = new ApplicationEntity();
        savedApplication.setId("test-app");
        when(applicationRepository.findById("test-app")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApplication);
        when(applicationVersionRepository.save(any(ApplicationVersionEntity.class))).thenAnswer(i -> i.getArgument(0));

        final CreateApplicationResponse response = applicationServiceBehavior.createApplication(request);

        assertNotNull(response);
        assertEquals("test-app", response.getApplicationId());
    }

    @Test
    void createApplication_shouldSaveApplication_withCorrectId() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("my-app");

        final ApplicationEntity savedApplication = new ApplicationEntity();
        savedApplication.setId("my-app");
        when(applicationRepository.findById("my-app")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApplication);
        when(applicationVersionRepository.save(any(ApplicationVersionEntity.class))).thenAnswer(i -> i.getArgument(0));

        applicationServiceBehavior.createApplication(request);

        final ArgumentCaptor<ApplicationEntity> captor = ArgumentCaptor.forClass(ApplicationEntity.class);
        verify(applicationRepository).save(captor.capture());
        assertEquals("my-app", captor.getValue().getId());
    }

    @Test
    void createApplication_shouldSaveDefaultVersion_withCorrectDefaults() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("app-x");

        final ApplicationEntity savedApplication = new ApplicationEntity();
        savedApplication.setId("app-x");
        when(applicationRepository.findById("app-x")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApplication);
        when(applicationVersionRepository.save(any(ApplicationVersionEntity.class))).thenAnswer(i -> i.getArgument(0));

        applicationServiceBehavior.createApplication(request);

        final ArgumentCaptor<ApplicationVersionEntity> captor = ArgumentCaptor.forClass(ApplicationVersionEntity.class);
        verify(applicationVersionRepository).save(captor.capture());
        final ApplicationVersionEntity version = captor.getValue();
        assertEquals("default", version.getId());
        assertTrue(version.getSupported());
        assertSame(savedApplication, version.getApplication());
    }

    @Test
    void createApplication_shouldGenerateNonNullAppKeyAndSecret() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("app-y");

        final ApplicationEntity savedApplication = new ApplicationEntity();
        savedApplication.setId("app-y");
        when(applicationRepository.findById("app-y")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApplication);
        when(applicationVersionRepository.save(any(ApplicationVersionEntity.class))).thenAnswer(i -> i.getArgument(0));

        applicationServiceBehavior.createApplication(request);

        final ArgumentCaptor<ApplicationVersionEntity> captor = ArgumentCaptor.forClass(ApplicationVersionEntity.class);
        verify(applicationVersionRepository).save(captor.capture());
        final ApplicationVersionEntity version = captor.getValue();
        assertNotNull(version.getApplicationKey());
        assertNotNull(version.getApplicationSecret());
    }

    @Test
    void createApplication_shouldGenerateUniqueAppKeys_acrossInvocations() throws Exception {
        final ApplicationEntity savedApp1 = new ApplicationEntity();
        savedApp1.setId("app-1");
        final ApplicationEntity savedApp2 = new ApplicationEntity();
        savedApp2.setId("app-2");

        when(applicationRepository.findById("app-1")).thenReturn(Optional.empty());
        when(applicationRepository.findById("app-2")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApp1, savedApp2);
        when(applicationVersionRepository.save(any(ApplicationVersionEntity.class))).thenAnswer(i -> i.getArgument(0));

        final CreateApplicationRequest request1 = new CreateApplicationRequest();
        request1.setApplicationId("app-1");
        applicationServiceBehavior.createApplication(request1);

        final CreateApplicationRequest request2 = new CreateApplicationRequest();
        request2.setApplicationId("app-2");
        applicationServiceBehavior.createApplication(request2);

        final ArgumentCaptor<ApplicationVersionEntity> captor = ArgumentCaptor.forClass(ApplicationVersionEntity.class);
        verify(applicationVersionRepository, times(2)).save(captor.capture());
        final String key1 = captor.getAllValues().get(0).getApplicationKey();
        final String key2 = captor.getAllValues().get(1).getApplicationKey();
        assertNotEquals(key1, key2);
    }

    @Test
    void createApplication_shouldThrowException_whenDuplicateApplicationId() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("existing-app");

        when(applicationRepository.findById("existing-app")).thenReturn(Optional.of(new ApplicationEntity()));
        when(localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION))
                .thenReturn(new GenericServiceException(ServiceError.DUPLICATE_APPLICATION, "Duplicate"));

        assertThrows(GenericServiceException.class, () -> applicationServiceBehavior.createApplication(request));
    }

    @Test
    void createApplication_shouldNotSaveApplication_whenDuplicateDetected() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("existing-app");

        when(applicationRepository.findById("existing-app")).thenReturn(Optional.of(new ApplicationEntity()));
        when(localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION))
                .thenReturn(new GenericServiceException(ServiceError.DUPLICATE_APPLICATION, "Duplicate"));

        assertThrows(GenericServiceException.class, () -> applicationServiceBehavior.createApplication(request));
        verify(applicationRepository, never()).save(any());
        verify(applicationVersionRepository, never()).save(any());
    }

    @Test
    void createApplication_shouldPropagateException_whenMasterKeyGenerationFails() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("app-fail");

        final ApplicationEntity savedApplication = new ApplicationEntity();
        savedApplication.setId("app-fail");
        when(applicationRepository.findById("app-fail")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApplication);
        doThrow(new GenericServiceException(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR, "Crypto error"))
                .when(masterKeyGenerationService).generateMasterKeyPairs(any(ApplicationEntity.class));

        assertThrows(GenericServiceException.class, () -> applicationServiceBehavior.createApplication(request));
    }

    @Test
    void createApplication_shouldNotSaveVersion_whenMasterKeyGenerationFails() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("app-fail");

        final ApplicationEntity savedApplication = new ApplicationEntity();
        savedApplication.setId("app-fail");
        when(applicationRepository.findById("app-fail")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenReturn(savedApplication);
        doThrow(new GenericServiceException(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR, "Crypto error"))
                .when(masterKeyGenerationService).generateMasterKeyPairs(any(ApplicationEntity.class));

        assertThrows(GenericServiceException.class, () -> applicationServiceBehavior.createApplication(request));
        verify(applicationVersionRepository, never()).save(any());
    }

    @Test
    void createApplication_shouldRethrowRuntimeException_whenUnexpectedErrorOccurs() throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId("app-runtime");

        when(applicationRepository.findById("app-runtime")).thenReturn(Optional.empty());
        when(applicationRepository.save(any(ApplicationEntity.class))).thenThrow(new RuntimeException("DB error"));

        assertThrows(RuntimeException.class, () -> applicationServiceBehavior.createApplication(request));
    }
}
