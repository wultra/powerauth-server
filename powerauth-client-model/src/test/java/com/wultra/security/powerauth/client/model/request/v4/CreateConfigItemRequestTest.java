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
package com.wultra.security.powerauth.client.model.request.v4;

import com.wultra.security.powerauth.client.model.enumeration.ConfigScope;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for bean validation of {@link CreateConfigItemRequest}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class CreateConfigItemRequestTest {

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        validatorFactory.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"base_url", "a", "key.with.dots", "key-with-dashes", "KEY_123"})
    void testValidKey(final String key) {
        final Set<ConstraintViolation<CreateConfigItemRequest>> violations = validator.validate(request(key));

        assertTrue(violations.isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad key!", "spaces here", "emoji😀", "slash/key", "quote\"key"})
    void testInvalidKey(final String key) {
        final Set<ConstraintViolation<CreateConfigItemRequest>> violations = validator.validate(request(key));

        assertFalse(violations.isEmpty());
    }

    @Test
    void testBlankKey() {
        final Set<ConstraintViolation<CreateConfigItemRequest>> violations = validator.validate(request(""));

        assertFalse(violations.isEmpty());
    }

    private static CreateConfigItemRequest request(final String key) {
        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId("app");
        request.setScope(ConfigScope.APPLICATION);
        request.setKey(key);
        request.setValue("value");
        return request;
    }
}
