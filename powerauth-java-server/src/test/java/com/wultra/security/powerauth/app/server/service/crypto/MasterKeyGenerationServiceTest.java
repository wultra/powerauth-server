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
package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.converter.MasterPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeysRecord;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MasterKeyGenerationServiceTest {

    @Mock
    private MasterKeyPairRepository masterKeyPairRepository;

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private MasterPrivateKeysConverter masterPrivateKeysConverter;

    @Mock
    private PublicKeysConverter publicKeysConverter;

    @Mock
    private AlgorithmQueryService algorithmQueryService;

    @InjectMocks
    private MasterKeyGenerationService masterKeyGenerationService;

    @BeforeAll
    static void initBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void generateMasterKeyPairs_shouldReturnSavedEntity_whenNewApplication() throws Exception {
        final ApplicationEntity app = app("app-1");
        final MasterKeyPairEntity saved = new MasterKeyPairEntity();
        saved.setName("saved");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenReturn(saved);

        final MasterKeyPairEntity result = masterKeyGenerationService.generateMasterKeyPairs(app);

        assertSame(saved, result);
    }

    @Test
    void generateMasterKeyPairs_shouldSetMasterKeyPublicBase64_whenNewApplication_EC_P256() throws Exception {
        final ApplicationEntity app = app("app-2");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-2")).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        final MasterKeyPairEntity result = masterKeyGenerationService.generateMasterKeyPairs(app);

        assertNotNull(result.getMasterKeyPublicBase64(), "P256 public key should be set");
        assertNotNull(result.getMasterKeyPrivateBase64(), "P256 private key should be set");
    }

    @Test
    void generateMasterKeyPairs_shouldNotSetV3Keys_whenEC_P256NotSupported() throws Exception {
        final ApplicationEntity app = app("app-3");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-3")).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P384));
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        final MasterKeyPairEntity result = masterKeyGenerationService.generateMasterKeyPairs(app);

        assertNull(result.getMasterKeyPublicBase64(), "P256 public key should not be generated");
        assertNull(result.getMasterKeyPrivateBase64(), "P256 private key should not be generated");
    }

    @Test
    void generateMasterKeyPairs_shouldWritePublicKeysToEntity_whenEC_P384Supported() throws Exception {
        final ApplicationEntity app = app("app-4");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-4")).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P384));
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        final MasterKeyPairEntity result = masterKeyGenerationService.generateMasterKeyPairs(app);

        assertEquals("encoded-public-keys", result.getMasterPublicKeys(), "Encoded public keys should be written to entity");
    }

    @Test
    void generateMasterKeyPairs_shouldWriteMlDsa65Keys_whenEC_P384_ML_L3Supported() throws Exception {
        final ApplicationEntity app = app("app-5");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-5")).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P384_ML_L3));
        final ArgumentCaptor<PublicKeyRegistry> publicRegistryCaptor = ArgumentCaptor.forClass(PublicKeyRegistry.class);
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), anyString()))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.NO_ENCRYPTION, "pk"));
        when(publicKeysConverter.toDBValue(publicRegistryCaptor.capture())).thenReturn("encoded-public-keys");
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        masterKeyGenerationService.generateMasterKeyPairs(app);

        final PublicKeyRegistry registry = publicRegistryCaptor.getValue();
        assertFalse(registry.getPublicKeys().isEmpty(), "Public key registry should contain generated keys");
    }

    @Test
    void generateMasterKeyPairs_shouldSkipV3KeyGeneration_whenKeysAlreadyPresent() throws Exception {
        final ApplicationEntity app = app("app-6");
        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setMasterKeyPrivateBase64("existing-private");
        existing.setMasterKeyPublicBase64("existing-public");
        // masterPrivateKeys is null → fresh registries used, no fromDBValue call needed

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-6")).thenReturn(existing);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        final MasterKeyPairEntity result = masterKeyGenerationService.generateMasterKeyPairs(app);

        assertEquals("existing-public", result.getMasterKeyPublicBase64(), "Pre-existing V3 key must not be overwritten");
        assertEquals("existing-private", result.getMasterKeyPrivateBase64(), "Pre-existing V3 private key must not be overwritten");
    }

    @Test
    void generateMasterKeyPairs_shouldUseEmptyRegistries_whenExistingEntityHasNullMasterPrivateKeys() throws Exception {
        final ApplicationEntity app = app("app-7");
        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        // masterPrivateKeys == null → branch: create new registries (no fromDBValue call)

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-7")).thenReturn(existing);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P384));
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        masterKeyGenerationService.generateMasterKeyPairs(app);

        verify(masterPrivateKeysConverter, never()).fromDBValue(any(), anyString());
        verify(publicKeysConverter, never()).fromDBValue(anyString());
    }

    @Test
    void generateMasterKeyPairs_shouldLoadExistingRegistries_whenMasterPrivateKeysPresent() throws Exception {
        final ApplicationEntity app = app("app-8");
        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setMasterPrivateKeys("existing-private-keys-blob");
        existing.setMasterPublicKeys("existing-public-keys-blob");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-8")).thenReturn(existing);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(masterPrivateKeysConverter.fromDBValue(any(), eq("app-8"))).thenReturn(new PrivateKeyRegistry());
        when(publicKeysConverter.fromDBValue("existing-public-keys-blob")).thenReturn(new PublicKeyRegistry());
        stubWriteRegistries();
        when(masterKeyPairRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        masterKeyGenerationService.generateMasterKeyPairs(app);

        verify(masterPrivateKeysConverter).fromDBValue(any(), eq("app-8"));
        verify(publicKeysConverter).fromDBValue("existing-public-keys-blob");
    }

    @Test
    void generateMasterKeyPairs_shouldThrowGenericServiceException_whenConverterFails() throws Exception {
        final ApplicationEntity app = app("app-9");
        final GenericServiceException expected = new GenericServiceException(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR, "error");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-9")).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(app)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), anyString()))
                .thenThrow(expected);

        assertThrows(GenericServiceException.class, () -> masterKeyGenerationService.generateMasterKeyPairs(app));
        verify(masterKeyPairRepository, never()).save(any());
    }

    // --- helpers ---

    private static ApplicationEntity app(String id) {
        final ApplicationEntity app = new ApplicationEntity();
        app.setId(id);
        return app;
    }

    private void stubWriteRegistries() throws GenericServiceException {
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), anyString()))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.NO_ENCRYPTION, "pk"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class)))
                .thenReturn("encoded-public-keys");
    }
}
