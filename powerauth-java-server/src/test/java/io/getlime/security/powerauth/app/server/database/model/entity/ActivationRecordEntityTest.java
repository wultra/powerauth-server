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
package io.getlime.security.powerauth.app.server.database.model.entity;

import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test for {@link ActivationRecordEntity}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
@Sql
@Transactional
@ActiveProfiles("test")
class ActivationRecordEntityTest {

    @Autowired
    private EntityManager entityManager;

    @Test
    void testPlatform_null() {
        final ActivationRecordEntity result = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");
        assertNotNull(result.getProtocol());
        assertEquals("powerauth", result.getProtocol());
    }

    @Test
    void testPlatform() {
        final ActivationRecordEntity result = entityManager.find(ActivationRecordEntity.class, "68c5ca56-b419-4653-949f-49061a4be886");
        assertNotNull(result.getProtocol());
        assertEquals("fido2", result.getProtocol());
    }
}
