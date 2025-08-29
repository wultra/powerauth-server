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
 *
 */

package com.wultra.security.powerauth.app.server.controller.validation;

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for authentication code validation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class VerifyAuthenticationRequestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setupValidator() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDownValidator() {
        factory.close();
    }

    private VerifyAuthenticationRequest buildBaseRequest(String authenticationCode) {
        final VerifyAuthenticationRequest req = new VerifyAuthenticationRequest();
        req.setActivationId("06c4d2d4-4bff-4ea7-b58c-5cfe8b7f0bb0");
        req.setApplicationKey("qjsBj6II/syLPs65BbNRyg==");
        req.setData("POST&L3BhL2xvZ2lu&vkueT796IGqdXlfVIJrB9A==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");
        req.setAuthenticationCode(authenticationCode);
        req.setAuthenticationCodeType(AuthenticationCodeType.POSSESSION_BIOMETRY);
        req.setAuthenticationVersion("4.0");
        return req;
    }

    @Test
    void validBase64AuthenticationCode_passesValidation() {
        final VerifyAuthenticationRequest req = buildBaseRequest("f0LKq3AVXO4unDIKhclgLfaxeMz4YBFJokAx8ZB6t2/ZfGzIQzdLHClynGqCNQ9O/0OUzOwWYEK/cS/CCJFqX4WkR8kRXpSFNz8BqmfkJwkhwS5WE1OTq+1P02GC6C0R");
        final Set<ConstraintViolation<VerifyAuthenticationRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    void invalidBase64AuthenticationCode_failsValidation() {
        final VerifyAuthenticationRequest req = buildBaseRequest("XXX~");
        final Set<ConstraintViolation<VerifyAuthenticationRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty(), "Expected violations for an invalid Base64 authentication code");
        assertTrue(violations.stream().anyMatch(v -> "authenticationCode".equals(v.getPropertyPath().toString())));
    }

    @Test
    void binaryLikeStringWithNul_failsValidation() {
        final String binary = "abc\u0000def";
        final VerifyAuthenticationRequest req = buildBaseRequest(binary);
        final Set<ConstraintViolation<VerifyAuthenticationRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v -> "authenticationCode".equals(v.getPropertyPath().toString())));
    }

    @Test
    void blankAuthenticationCode_triggersNotBlank() {
        final VerifyAuthenticationRequest req = buildBaseRequest("   ");
        final Set<ConstraintViolation<VerifyAuthenticationRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v ->
                        "authenticationCode".equals(v.getPropertyPath().toString()) && v.getMessage().equals("Authentication code must not be empty when verifying authentication"))
        );
    }

}
