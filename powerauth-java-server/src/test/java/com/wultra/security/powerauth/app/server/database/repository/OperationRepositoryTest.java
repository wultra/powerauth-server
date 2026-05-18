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
package com.wultra.security.powerauth.app.server.database.repository;

import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Transactional;
import com.wultra.security.powerauth.app.server.database.model.entity.OperationEntity;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationRepository}.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
@Import({JsonMapper.class, ConcurrentMapCacheManager.class})
@Transactional
@Sql
class OperationRepositoryTest {

    private static final String USER_ID = "testUser";
    private static final List<String> APPLICATION_IDS = Arrays.asList("PA_Tests", "PA_Tests2", "PA_Tests3");
    private static final String ACTIVATION_ID1 = "e43a5dec-afea-4a10-a80b-b2183399f16b";
    private static final String ACTIVATION_ID2 = "68c5ca56-b419-4653-949f-49061a4be886";
    private static final Pageable PAGEABLE = PageRequest.of(0, 10);

    @Autowired
    private OperationRepository operationRepository;

    @Autowired
    private ActivationRepository activationRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Tests finding an operation by its ID.
     * Asserts that the operation is present.
     */
    @Test
    void testFindOperationById() {
        final Optional<OperationEntity> operation = operationRepository.findOperationWithoutLock("0f038bac-6c94-45eb-b3a9-f92e809e8ea4");
        assertTrue(operation.isPresent());
    }

    /**
     * Tests finding operations for a user with specific activation ID filters.
     * Asserts non-null operation lists and checks the size for different activation IDs.
     */
    @Test
    void testFindOperationsWithActivationIdFilter() {
        final List<OperationEntity> operations1 = operationRepository.
                findAllOperationsForUser(USER_ID, APPLICATION_IDS, ACTIVATION_ID1, null, PAGEABLE).toList();

        assertNotNull(operations1);
        assertEquals(3, operations1.size());

        final List<OperationEntity> operations2 = operationRepository.
                findAllOperationsForUser(USER_ID, APPLICATION_IDS, ACTIVATION_ID2, null, PAGEABLE).toList();

        assertNotNull(operations2);
        assertEquals(4, operations2.size());
    }

    /**
     * Tests finding operations for a user with activation flag filters.
     * Asserts non-null operation lists and checks the size for different sets of activation flags.
     */
    @Test
    void testFindOperationsWithActivationFlagFilter() {
        final List<String> activationFlags1 = activationRepository.findActivationWithoutLock(ACTIVATION_ID1).get().getFlags();
        final List<String> activationFlags2 = activationRepository.findActivationWithoutLock(ACTIVATION_ID2).get().getFlags();
        final List<String> nonExistingFlags = List.of("NOT_EXISTING");
        final List<OperationEntity> operations1 = operationRepository.
                findAllOperationsForUser(USER_ID, APPLICATION_IDS, null, activationFlags1, PAGEABLE).toList();

        assertNotNull(operations1);
        assertEquals(6, operations1.size());

        final List<OperationEntity> operations2 = operationRepository.
                findAllOperationsForUser(USER_ID, APPLICATION_IDS, null, activationFlags2, PAGEABLE).toList();

        assertNotNull(operations2);
        assertEquals(5, operations2.size());

        final List<OperationEntity> operations3 = operationRepository.
                findAllOperationsForUser(USER_ID, APPLICATION_IDS, null, nonExistingFlags, PAGEABLE).toList();

        assertNotNull(operations3);
        assertEquals(2, operations3.size());
    }

    /**
     * Tests that fetching {@link OperationEntity} using the {@link OperationRepository} gracefully handles legacy
     * or unsupported values stored in the {@code signature_type} column of {@code pa_operation} table.
     */
    @Test
    void testHandlingUnsupportedSignatureTypes() {
        // Assert unsupported signature types are set
        final String rawSignatureTypes = jdbcTemplate.queryForObject("SELECT signature_type FROM pa_operation WHERE id = '2067b5d1-1c50-43eb-99df-847830e4807a'", String.class);
        assertEquals("possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry",  rawSignatureTypes);

        // Test the handling
        final Optional<OperationEntity> operation = operationRepository.findOperationWithoutLock("2067b5d1-1c50-43eb-99df-847830e4807a");
        assertTrue(operation.isPresent());

        // Unsupported signature types are ignored
        assertThat(operation.get().getSignatureType())
                .hasSize(3)
                .containsExactlyInAnyOrder(PowerAuthCodeType.POSSESSION, PowerAuthCodeType.POSSESSION_KNOWLEDGE, PowerAuthCodeType.POSSESSION_BIOMETRY);
    }

}
