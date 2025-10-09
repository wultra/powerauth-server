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
package com.wultra.security.powerauth.client.model.request;

import com.wultra.security.powerauth.client.model.enumeration.ActivationTransferType;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for {@link InitActivationRequest}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class InitActivationRequestTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @Test
    void testValidRequest() {
        final InitActivationRequest request = createValidRequest();

        final Set<ConstraintViolation<InitActivationRequest>> violations = validator.validate(request);

        assertTrue(violations.isEmpty(), "Valid request should not have validation errors");
    }

    @Test
    void testValidationTransferTypeMissing() {
        final InitActivationRequest request = createValidRequest();
        request.setParentActivationId("parent-activation-id");
        request.setTransferType(null);

        final Set<ConstraintViolation<InitActivationRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty(), "Valid request should have validation errors");
        final var constraintViolation = violations.iterator().next();
        assertEquals("Transfer type is mandatory when parent activation ID is present", constraintViolation.getMessage());
    }

    @Test
    void testValidationTransferTypePresent() {
        final InitActivationRequest request = createValidRequest();
        request.setParentActivationId("parent-activation-id");
        request.setTransferType(ActivationTransferType.MOVE);

        final Set<ConstraintViolation<InitActivationRequest>> violations = validator.validate(request);

        assertTrue(violations.isEmpty(), "Valid request should not have validation errors");
    }

    @Test
    void testValidationParentActivationIdMissing() {
        final InitActivationRequest request = createValidRequest();
        request.setParentActivationId(null);
        request.setTransferType(ActivationTransferType.MOVE);

        final Set<ConstraintViolation<InitActivationRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty(), "Valid request should have validation errors");
        final var constraintViolation = violations.iterator().next();
        assertEquals("Parent activation ID is mandatory when transfer type is present", constraintViolation.getMessage());
    }

    private InitActivationRequest createValidRequest() {
        final InitActivationRequest request = new InitActivationRequest();
        request.setUserId("test-user");
        request.setApplicationId("test-app");
        request.setMaxFailureCount(5L);
        request.setTimestampActivationExpire(Date.from(Instant.now().plus(Duration.ofDays(1))));
        return request;
    }
}
