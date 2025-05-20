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
package io.getlime.security.powerauth.app.server.service.persistence;

import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationConfigEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationConfigRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ApplicationConfigService}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class ApplicationConfigServiceTest {

    @SpringBootTest
    @ActiveProfiles("test")
    @Nested
    @Sql("ApplicationConfigServiceTest.sql")
    @Transactional
    class Encrypted {

        @Autowired
        private ApplicationConfigService tested;

        @Autowired
        private ApplicationConfigRepository repository;

        @Autowired
        private EntityManager entityManager;

        @Test
        void testCreate() throws Exception {
            final ApplicationEntity application = entityManager.find(ApplicationEntity.class, 21L);
            final ApplicationConfigService.ApplicationConfig source
                    = new ApplicationConfigService.ApplicationConfig(null, application, "oauth2_providers", List.of("client_secret"));

            tested.createOrUpdate(source);

            final Optional<ApplicationConfigService.ApplicationConfig> result = tested.findByApplicationIdAndKey("PA_Tests", "oauth2_providers");
            assertTrue(result.isPresent());
            assertEquals(List.of("client_secret"), result.get().values());

            final Optional<ApplicationConfigEntity> entity = repository.findByApplicationIdAndKey("PA_Tests", "oauth2_providers");
            assertTrue(entity.isPresent());
            assertEquals(EncryptionMode.AES_HMAC, entity.get().getEncryptionMode());
            assertFalse(entity.get().getValues().contains("client_secret"));
        }
    }

    @SpringBootTest
    @ActiveProfiles("test")
    @Nested
    @TestPropertySource(properties = "powerauth.server.db.master.encryption.key=")
    @Sql("ApplicationConfigServiceTest.sql")
    @Transactional
    class Plain {

        @Autowired
        private ApplicationConfigService tested;

        @Autowired
        private ApplicationConfigRepository repository;

        @Autowired
        private EntityManager entityManager;

        @Test
        void testCreate() throws Exception {
            final ApplicationEntity application = entityManager.find(ApplicationEntity.class, 21L);
            final ApplicationConfigService.ApplicationConfig source
                    = new ApplicationConfigService.ApplicationConfig(null, application, "oauth2_providers", List.of("client_secret"));

            tested.createOrUpdate(source);

            final Optional<ApplicationConfigService.ApplicationConfig> result = tested.findByApplicationIdAndKey("PA_Tests", "oauth2_providers");
            assertTrue(result.isPresent());
            assertEquals(List.of("client_secret"), result.get().values());

            final Optional<ApplicationConfigEntity> entity = repository.findByApplicationIdAndKey("PA_Tests", "oauth2_providers");
            assertTrue(entity.isPresent());
            assertEquals(EncryptionMode.NO_ENCRYPTION, entity.get().getEncryptionMode());
            assertEquals("[ \"client_secret\" ]", entity.get().getValues());
        }
    }
}
