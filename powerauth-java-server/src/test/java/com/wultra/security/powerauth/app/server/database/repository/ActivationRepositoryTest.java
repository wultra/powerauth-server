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
package com.wultra.security.powerauth.app.server.database.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link ActivationRepository}.
 *
 * @author Vit Kotacka, vit.kotacka@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
@Sql
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class ActivationRepositoryTest {

    private static final String APP_ID = "test-app-activation";
    private static final String OTHER_APP_ID = "other-app-activation";

    /** Activation code present in app-100. */
    private static final String EXISTING_CODE = "AAAAA-AAAAA-BBBBB-BBBBB";

    /**
     * Shares the first 11 characters ("AAAAA-AAAAA") with {@link #EXISTING_CODE} but has a different suffix.
     * The old LIKE-based query would incorrectly count this as a collision; the current = query must not.
     */
    private static final String SAME_PREFIX_DIFFERENT_SUFFIX = "AAAAA-AAAAA-CCCCC-CCCCC";

    /** Code that does not exist in any application. */
    private static final String NONEXISTENT_CODE = "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ";

    @Autowired
    private ActivationRepository activationRepository;

    void getActivationCountByActivationCode_shouldReturnOne_whenCodeExists() {
        assertEquals(1L, activationRepository.getActivationCountByActivationCode(APP_ID, EXISTING_CODE));
    }

    @Test
    void getActivationCountByActivationCode_shouldReturnZero_whenSamePrefixButDifferentSuffix() {
        // Regression test: the old LIKE ':prefix%' query returned 1 here because SAME_PREFIX_DIFFERENT_SUFFIX
        // shares the first 11 characters with EXISTING_CODE. The rewritten = query must return 0.
        assertEquals(0L, activationRepository.getActivationCountByActivationCode(APP_ID, SAME_PREFIX_DIFFERENT_SUFFIX));
    }

    @Test
    void getActivationCountByActivationCode_shouldReturnZero_whenCodeDoesNotExist() {
        assertEquals(0L, activationRepository.getActivationCountByActivationCode(APP_ID, NONEXISTENT_CODE));
    }

    @Test
    void getActivationCountByActivationCode_shouldReturnZero_whenCodeBelongsToDifferentApplication() {
        // EXISTING_CODE is only in APP_ID, not in OTHER_APP_ID
        assertEquals(0L, activationRepository.getActivationCountByActivationCode(OTHER_APP_ID, EXISTING_CODE));
    }
}
