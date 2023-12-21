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

    private static final String userId = "testUser";
    private static final List<String> applicationIds = Arrays.asList("PA_Tests", "PA_Tests2");
    private static final String activationId1 = "e43a5dec-afea-4a10-a80b-b2183399f16b";
    private static final String activationId2 = "68c5ca56-b419-4653-949f-49061a4be886";
    private static final Pageable pageable = PageRequest.of(0, 10);

    @Autowired
    private OperationRepository operationRepository;

    @Autowired
    private ActivationRepository activationRepository;

    /**
     * Tests finding an operation by its ID.
     * Asserts that the operation is present.
     */
    @Test
    void testFindOperationById() {
        final Optional<OperationEntity> operation = operationRepository.findOperation("0f038bac-6c94-45eb-b3a9-f92e809e8ea4");
        assertTrue(operation.isPresent());
    }

    /**
     * Tests finding all operations for a user without any activation filters.
     * Asserts that the list of operations is not null and checks the size.
     */
    @Test
    void testFindOperationsWithoutActivationFilter() {
        final List<OperationEntity> operations = operationRepository.
                findAllOperationsForUser(userId, applicationIds, null, null, pageable).toList();

        assertNotNull(operations);
        assertEquals(6, operations.size());
    }

    /**
     * Tests finding operations for a user with specific activation ID filters.
     * Asserts non-null operation lists and checks the size for different activation IDs.
     */
    @Test
    void testFindOperationsWithActivationIdFilter() {
        final List<OperationEntity> operations1 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, activationId1, null, pageable).toList();

        assertNotNull(operations1);
        assertEquals(3, operations1.size());

        final List<OperationEntity> operations2 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, activationId2, null, pageable).toList();

        assertNotNull(operations2);
        assertEquals(4, operations2.size());
    }

    /**
     * Tests finding operations for a user with activation flag filters.
     * Asserts non-null operation lists and checks the size for different sets of activation flags.
     */
    @Test
    void testFindOperationsWithActivationFlagFilter() {
        final List<String> activationFlags1 = activationRepository.findActivationWithoutLock(activationId1).getFlags();
        final List<String> activationFlags2 = activationRepository.findActivationWithoutLock(activationId2).getFlags();
        final List<String> nonExistingFlags = List.of("NOT_EXISTING");
        final List<OperationEntity> operations1 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, null, activationFlags1, pageable).toList();

        assertNotNull(operations1);
        assertEquals(6, operations1.size());

        final List<OperationEntity> operations2 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, null, activationFlags2, pageable).toList();

        assertNotNull(operations2);
        assertEquals(5, operations2.size());

        final List<OperationEntity> operations3 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, null, nonExistingFlags, pageable).toList();

        assertNotNull(operations3);
        assertEquals(2, operations3.size());
    }

    /**
     * Tests finding all operations for a user with both activation ID and activation flag filters.
     * Asserts non-null operation lists and verifies the correct number of operations for different activation flags and IDs.
     */
    @Test
    void testFindAllOperationsForUser() {
        final List<String> activationFlags1 = activationRepository.findActivationWithoutLock(activationId1).getFlags();

        final List<OperationEntity> operations1 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, activationId1, activationFlags1, pageable).toList();

        assertNotNull(operations1);
        assertEquals(3, operations1.size());

        final List<String> activationFlags2 = activationRepository.findActivationWithoutLock(activationId2).getFlags();

        final List<OperationEntity> operations2 = operationRepository.
                findAllOperationsForUser(userId, applicationIds, activationId2, activationFlags2, pageable).toList();

        assertNotNull(operations2);
        assertEquals(3, operations2.size());
    }
}
