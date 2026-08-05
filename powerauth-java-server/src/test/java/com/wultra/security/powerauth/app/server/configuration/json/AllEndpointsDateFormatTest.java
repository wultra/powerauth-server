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

package com.wultra.security.powerauth.app.server.configuration.json;

import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.lang.reflect.Field;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Paranoid coverage test asserting that <em>every</em> {@link Date} field on <em>every</em> public REST
 * response contract listed in the issue #2436 analysis is serialized uniformly, and that the
 * {@link LegacyDateJacksonModule} switches all of them together.
 * <p>
 * Because the module registers a serializer for {@link Date} on the shared application {@code ObjectMapper},
 * the fix is global: no wire DTO uses a different temporal type (there are no {@code LocalDateTime} /
 * {@code Instant} fields) and no {@code Date} field carries a {@code @JsonFormat} override, so the flag
 * governs all of them consistently.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class AllEndpointsDateFormatTest {

    private static final Date FIXED_DATE = new Date(1785926829449L);

    private static final Pattern Z_PATTERN =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");

    private static final Pattern OFFSET_PATTERN =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\+00:00");

    static Stream<Arguments> responseContracts() {
        return Stream.of(
                Arguments.of("v3 OperationDetailResponse",
                        com.wultra.security.powerauth.client.model.response.v3.OperationDetailResponse.class,
                        List.of("timestampCreated", "timestampExpires", "timestampFinalized")),
                Arguments.of("v4 OperationDetailResponse",
                        com.wultra.security.powerauth.client.model.response.v4.OperationDetailResponse.class,
                        List.of("timestampCreated", "timestampExpires", "timestampFinalized")),
                Arguments.of("v3 GetActivationStatusResponse",
                        com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse.class,
                        List.of("timestampCreated", "timestampLastUsed", "timestampLastChange", "timestampBlockExpire")),
                Arguments.of("v4 GetActivationStatusResponse",
                        com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse.class,
                        List.of("timestampCreated", "timestampLastUsed", "timestampLastChange", "timestampBlockExpire")),
                Arguments.of("Activation (activation list entity)",
                        Activation.class,
                        List.of("timestampCreated", "timestampLastUsed", "timestampLastChange", "timestampBlockExpire")),
                Arguments.of("SignatureAuditItem",
                        SignatureAuditItem.class,
                        List.of("timestampCreated")),
                Arguments.of("ActivationHistoryItem",
                        ActivationHistoryItem.class,
                        List.of("timestampCreated")),
                Arguments.of("GetSystemStatusResponse",
                        GetSystemStatusResponse.class,
                        List.of("buildTime", "timestamp"))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("responseContracts")
    void testDefaultFormatUsesZ(final String label, final Class<?> type, final List<String> dateFields) throws Exception {
        final ObjectMapper mapper = JsonMapper.builder().build();
        final JsonNode node = mapper.valueToTree(instanceWithDates(type, dateFields));

        for (final String field : dateFields) {
            final JsonNode value = node.get(field);
            assertTrue(value.isString(), label + "." + field + " must be a JSON string, never a number");
            assertFalse(value.isNumber(), label + "." + field + " must not be a numeric epoch value");
            assertTrue(Z_PATTERN.matcher(value.asString()).matches(),
                    label + "." + field + " must use the Z designator by default, was: " + value.asString());
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("responseContracts")
    void testLegacyFormatUsesNumericOffset(final String label, final Class<?> type, final List<String> dateFields) throws Exception {
        final ObjectMapper mapper = JsonMapper.builder()
                .addModule(new LegacyDateJacksonModule())
                .build();
        final JsonNode node = mapper.valueToTree(instanceWithDates(type, dateFields));

        for (final String field : dateFields) {
            final JsonNode value = node.get(field);
            assertTrue(OFFSET_PATTERN.matcher(value.asString()).matches(),
                    label + "." + field + " must use the +00:00 offset in legacy mode, was: " + value.asString());
        }
    }

    private static Object instanceWithDates(final Class<?> type, final List<String> dateFields) throws Exception {
        final Object instance = type.getDeclaredConstructor().newInstance();
        for (final String fieldName : dateFields) {
            final Field field = type.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(instance, FIXED_DATE);
        }
        return instance;
    }

}
