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
 */
package io.getlime.security.powerauth.app.server.database.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationRepository}.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@DataJpaTest
@ActiveProfiles("test")
@Import(ObjectMapper.class)
@Sql
class OperationRepositoryTest {

    @Autowired
    private OperationRepository operationRepository;

    @Autowired
    private ActivationRepository activationRepository;

    @Test
    void testFindOperationById() {
        final Optional<OperationEntity> operation = operationRepository.findOperation("0f038bac-6c94-45eb-b3a9-f92e809e8ea4");
        assertTrue(operation.isPresent());
    }

    @Test
    void testFindAllOperationsForUser() {
        final String userId = "testUser";
        final List<String> applicationIds = Arrays.asList("PA_Tests", "PA_Tests2");
        final Optional<String> activationId = Optional.of("e43a5dec-afea-4a10-a80b-b2183399f16b");
        final Pageable pageable = PageRequest.of(0, 10);
        final List<String> activationFlags = activationRepository.findActivationWithoutLock(activationId.get()).getFlags();

        final List<OperationEntity> operations = operationRepository.
                findAllOperationsForUser(userId, applicationIds, activationId, activationFlags, pageable).collect(Collectors.toList());

        assertNotNull(operations);
        assertNotEquals(0, operations.size());

        operations.forEach(op -> {
            assertEquals(op.getActivationId(), activationId.get());
            assertTrue(activationFlags.contains(op.getActivationFlag()));
        });
    }

    @Test
    void testFindAllOperationsForUserWithoutActivationIdFilter() {
        final String userId = "testUser";
        final List<String> applicationIds = Arrays.asList("PA_Tests", "PA_Tests2");
        final Pageable pageable = PageRequest.of(0, 10);

        final List<OperationEntity> operations = operationRepository.
                findAllOperationsForUser(userId, applicationIds, Optional.empty(), null, pageable).collect(Collectors.toList());

        assertNotNull(operations);
        assertEquals(3, operations.size());
        assertNull(operations.get(1).getActivationFlag());
    }

    @Test
    void testFindAllOperationsForUserWithoutActivationFlagFilter() {
        final String userId = "testUser";
        final List<String> applicationIds = Arrays.asList("PA_Tests", "PA_Tests2");
        final Optional<String> activationId = Optional.of("e43a5dec-afea-4a10-a80b-b2183399f16b");
        final Pageable pageable = PageRequest.of(0, 10);

        final List<OperationEntity> operations = operationRepository.
                findAllOperationsForUser(userId, applicationIds, activationId, null, pageable).collect(Collectors.toList());

        assertNotNull(operations);
        assertEquals(2, operations.size());
        assertEquals("test-flag1", operations.get(0).getActivationFlag());
        assertNull(operations.get(1).getActivationFlag());
        operations.forEach(op -> {
            assertEquals(op.getActivationId(), activationId.get());
        });
    }
}
