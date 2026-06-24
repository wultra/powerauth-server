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
 */
package com.wultra.security.powerauth.app.server.service.persistence;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ConfigStoreEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.database.repository.ConfigStoreRepository;
import com.wultra.security.powerauth.app.server.service.persistence.ConfigStoreService.ConfigStoreItem;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for {@link ConfigStoreService}, focused on database row-level encryption at rest.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
@Sql("ConfigStoreServiceTest.sql")
@Transactional
class ConfigStoreItemServiceTest {

    private static final String APP_ID = "PA_ConfigStore_Tests";
    private static final long APP_RID = 221L;
    private static final String ACTIVATION_ID = "cf9a1100-0000-4000-8000-000000000001";

    @Autowired
    private ConfigStoreService tested;

    @Autowired
    private ConfigStoreRepository repository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void testApplicationLevel_encryptsAtRestAndDecryptsOnRead() throws Exception {
        final ApplicationEntity application = entityManager.find(ApplicationEntity.class, APP_RID);
        final String plaintext = "{\"base_url\":\"https://secret.example.com\"}";
        tested.createOrUpdate(new ConfigStoreItem(null, application, null, ConfigScope.APPLICATION, plaintext, null, null));

        // Read path decrypts back to the original document.
        final Optional<ConfigStoreItem> read = tested.findApplicationLevel(APP_ID, ConfigScope.APPLICATION);
        assertTrue(read.isPresent());
        assertEquals(plaintext, read.get().configData());

        // At-rest the stored document is encrypted (AEAD_KMAC) and does not contain the plaintext.
        final Optional<ConfigStoreEntity> stored = repository.findByApplicationAndScope(APP_ID, ConfigScope.APPLICATION);
        assertTrue(stored.isPresent());
        assertEquals(EncryptionAlgorithm.AEAD_KMAC, stored.get().getEncryptionAlgorithm());
        assertFalse(stored.get().getConfigData().contains("secret.example.com"));
    }

    @Test
    void testPerDevice_encryptsAtRestAndDecryptsOnRead() throws Exception {
        final ApplicationEntity application = entityManager.find(ApplicationEntity.class, APP_RID);
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, ACTIVATION_ID);
        final String plaintext = "{\"device_token\":\"per-device-secret-value\"}";
        tested.createOrUpdate(new ConfigStoreItem(null, application, activation, ConfigScope.ACTIVATION, plaintext, null, null));

        // Read path decrypts back to the original document (key derivation includes the activation).
        final Optional<ConfigStoreItem> read = tested.findByActivationId(ACTIVATION_ID);
        assertTrue(read.isPresent());
        assertEquals(plaintext, read.get().configData());
        assertEquals(ConfigScope.ACTIVATION, read.get().scope());

        // At-rest the stored document is encrypted (AEAD_KMAC) and does not contain the plaintext.
        final Optional<ConfigStoreEntity> stored = repository.findByActivationId(ACTIVATION_ID);
        assertTrue(stored.isPresent());
        assertEquals(EncryptionAlgorithm.AEAD_KMAC, stored.get().getEncryptionAlgorithm());
        assertFalse(stored.get().getConfigData().contains("per-device-secret-value"));
    }

    @Test
    void testUpdate_reEncryptsAndPreservesDocument() throws Exception {
        final ApplicationEntity application = entityManager.find(ApplicationEntity.class, APP_RID);
        tested.createOrUpdate(new ConfigStoreItem(null, application, null, ConfigScope.APPLICATION, "{\"a\":1}", null, null));

        final ConfigStoreItem existing = tested.findApplicationLevel(APP_ID, ConfigScope.APPLICATION).orElseThrow();
        tested.createOrUpdate(new ConfigStoreItem(existing.id(), application, null, ConfigScope.APPLICATION, "{\"a\":1,\"b\":2}", null, null));

        final Optional<ConfigStoreItem> read = tested.findApplicationLevel(APP_ID, ConfigScope.APPLICATION);
        assertTrue(read.isPresent());
        assertEquals("{\"a\":1,\"b\":2}", read.get().configData());
        assertEquals(existing.id(), read.get().id());

        final Optional<ConfigStoreEntity> stored = repository.findByApplicationAndScope(APP_ID, ConfigScope.APPLICATION);
        assertTrue(stored.isPresent());
        assertEquals(EncryptionAlgorithm.AEAD_KMAC, stored.get().getEncryptionAlgorithm());
    }

    @Test
    void testDeleteByActivationId_removesPerDeviceRecord() throws Exception {
        final ApplicationEntity application = entityManager.find(ApplicationEntity.class, APP_RID);
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, ACTIVATION_ID);
        tested.createOrUpdate(new ConfigStoreItem(null, application, activation, ConfigScope.ACTIVATION, "{\"k\":\"v\"}", null, null));
        assertTrue(repository.findByActivationId(ACTIVATION_ID).isPresent());

        tested.deleteByActivationId(ACTIVATION_ID);

        assertTrue(repository.findByActivationId(ACTIVATION_ID).isEmpty());
    }

    @Test
    void testAssociatedDataBinding_relocatedCiphertextFailsToDecrypt() throws Exception {
        final ApplicationEntity application = entityManager.find(ApplicationEntity.class, APP_RID);
        tested.createOrUpdate(new ConfigStoreItem(null, application, null, ConfigScope.APPLICATION, "{\"x\":\"y\"}", null, null));

        // Sanity: the record decrypts in its original (APPLICATION) context.
        assertTrue(tested.findApplicationLevel(APP_ID, ConfigScope.APPLICATION).isPresent());

        // Relocate the ciphertext to a different scope context without re-encrypting (simulating a row
        // that was moved/tampered). The scope is part of the AEAD associated data but not the key.
        final ConfigStoreEntity entity = repository.findByApplicationAndScope(APP_ID, ConfigScope.APPLICATION).orElseThrow();
        entity.setScope(ConfigScope.ACTIVATION);
        repository.save(entity);
        entityManager.flush();

        // The associated data no longer matches the ciphertext, so AEAD verification fails and the record
        // is skipped rather than returning data lifted from a foreign context.
        assertTrue(tested.findApplicationLevel(APP_ID, ConfigScope.ACTIVATION).isEmpty());
    }
}

