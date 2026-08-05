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

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.client.model.response.v3.OperationDetailResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validates the Jackson 3 date wire format and the property-gated legacy override described in the
 * issue #2436 analysis.
 * <p>
 * Core facts under test:
 * <ul>
 *     <li>PowerAuth REST/callback timestamps have always been serialized as ISO-8601 date-time
 *     <em>strings</em>, never as numeric epoch values.</li>
 *     <li>Jackson 3 (as of wultra-core 2.2.0) emits the UTC zone as the {@code Z} designator, whereas
 *     Jackson 2 emitted the numeric {@code +00:00} offset. That single change (not a string/number
 *     change) is the actual cause of the reported client breakage.</li>
 *     <li>The {@link LegacyDateJacksonModule} restores the {@code +00:00} form for both the application
 *     {@code ObjectMapper} (main REST API) and the callback {@code DefaultRestClient}, on serialization
 *     only, without altering deserialization.</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class LegacyDateFormatTest {

    /**
     * Fixed instant 2026-08-05T10:47:09.449Z, mirroring the timestamp from the reported callback log.
     */
    private static final Date FIXED_DATE = new Date(1785926829449L);

    private static final Pattern Z_PATTERN =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");

    private static final Pattern OFFSET_PATTERN =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\+00:00");

    /**
     * The default Jackson 3 mapper (as used by both the Spring MVC message converter and the callback
     * {@code DefaultRestClient} default codec) serializes a {@link Date} as a textual ISO-8601 value
     * terminated by {@code Z}.
     */
    @Test
    void testDefaultMapperSerializesDateAsIsoStringWithZ() {
        final ObjectMapper mapper = JsonMapper.builder().build();

        final JsonNode node = mapper.valueToTree(callbackShapedMap());
        final JsonNode timestamp = node.get("timestampExpires");

        assertTrue(timestamp.isString(), "Timestamp must be serialized as a JSON string, never as a number");
        assertFalse(timestamp.isNumber(), "Timestamp must not be serialized as a numeric epoch value");
        assertTrue(Z_PATTERN.matcher(timestamp.asString()).matches(),
                "Default Jackson 3 output must use the Z designator, was: " + timestamp.asString());
        assertEquals("2026-08-05T10:47:09.449Z", timestamp.asString());
    }

    /**
     * With the legacy module registered, the same {@link Date} is serialized as a textual ISO-8601 value
     * using the numeric {@code +00:00} UTC offset, matching the Jackson 2 / pre-2.2.0 wire format.
     */
    @Test
    void testLegacyModuleSerializesDateWithNumericOffset() {
        final ObjectMapper mapper = JsonMapper.builder()
                .addModule(new LegacyDateJacksonModule())
                .build();

        final JsonNode node = mapper.valueToTree(callbackShapedMap());
        final JsonNode timestamp = node.get("timestampExpires");

        assertTrue(timestamp.isString());
        assertTrue(OFFSET_PATTERN.matcher(timestamp.asString()).matches(),
                "Legacy output must use the +00:00 offset, was: " + timestamp.asString());
        assertEquals("2026-08-05T10:47:09.449+00:00", timestamp.asString());
    }

    /**
     * The main REST API DTO {@link OperationDetailResponse} exhibits the same default behaviour: its
     * {@link Date} fields serialize as ISO-8601 strings ending with {@code Z}.
     */
    @Test
    void testOperationDetailResponseDefaultUsesZ() {
        final ObjectMapper mapper = JsonMapper.builder().build();
        final OperationDetailResponse response = operationDetailResponse();

        final JsonNode node = mapper.valueToTree(response);

        for (final String field : new String[]{"timestampCreated", "timestampExpires", "timestampFinalized"}) {
            final JsonNode timestamp = node.get(field);
            assertTrue(timestamp.isString(), field + " must be a JSON string");
            assertTrue(Z_PATTERN.matcher(timestamp.asString()).matches(),
                    field + " must use the Z designator by default, was: " + timestamp.asString());
        }
    }

    /**
     * The legacy module applied to the {@link OperationDetailResponse} restores the {@code +00:00} form.
     */
    @Test
    void testOperationDetailResponseLegacyUsesOffset() {
        final ObjectMapper mapper = JsonMapper.builder()
                .addModule(new LegacyDateJacksonModule())
                .build();
        final OperationDetailResponse response = operationDetailResponse();

        final JsonNode node = mapper.valueToTree(response);

        for (final String field : new String[]{"timestampCreated", "timestampExpires", "timestampFinalized"}) {
            final JsonNode timestamp = node.get(field);
            assertTrue(OFFSET_PATTERN.matcher(timestamp.asString()).matches(),
                    field + " must use the +00:00 offset in legacy mode, was: " + timestamp.asString());
        }
    }

    /**
     * The legacy module only affects serialization; deserialization stays lenient and continues to accept
     * both the {@code Z} and the {@code +00:00} representations, mapping them to the same instant.
     */
    @Test
    void testLegacyModuleDeserializationRemainsLenient() {
        final ObjectMapper mapper = JsonMapper.builder()
                .addModule(new LegacyDateJacksonModule())
                .build();

        final Date fromZ = mapper.readValue("\"2026-08-05T10:47:09.449Z\"", Date.class);
        final Date fromOffset = mapper.readValue("\"2026-08-05T10:47:09.449+00:00\"", Date.class);

        assertEquals(FIXED_DATE, fromZ);
        assertEquals(FIXED_DATE, fromOffset);
    }

    /**
     * The application mapper customizer wires the legacy module only when the flag is enabled, proving the
     * main REST API path is switched by {@code powerauth.service.rest.date.legacyFormatEnabled}.
     */
    @Test
    void testCustomizerAppliesLegacyModuleWhenFlagEnabled() {
        assertTrue(OFFSET_PATTERN.matcher(serializeViaCustomizer(true)).matches(),
                "With the flag enabled the customizer must produce +00:00");
        assertTrue(Z_PATTERN.matcher(serializeViaCustomizer(false)).matches(),
                "With the flag disabled the customizer must keep the Jackson 3 default Z");
    }

    private String serializeViaCustomizer(final boolean legacyEnabled) {
        final PowerAuthServiceConfiguration configuration = new PowerAuthServiceConfiguration();
        configuration.setRestDateLegacyFormatEnabled(legacyEnabled);
        final JsonMapperBuilderCustomizer customizer = configuration.jsonMapperBuilderCustomizer();

        final JsonMapper.Builder builder = JsonMapper.builder();
        customizer.customize(builder);
        final ObjectMapper mapper = builder.build();

        return mapper.valueToTree(callbackShapedMap()).get("timestampExpires").asString();
    }

    private static Map<String, Object> callbackShapedMap() {
        final Map<String, Object> map = new LinkedHashMap<>();
        map.put("operationId", "edef9d7e-1500-4cf9-8366-ecb68240c06d");
        map.put("timestampExpires", FIXED_DATE);
        return map;
    }

    private static OperationDetailResponse operationDetailResponse() {
        final OperationDetailResponse response = new OperationDetailResponse();
        response.setTimestampCreated(FIXED_DATE);
        response.setTimestampExpires(FIXED_DATE);
        response.setTimestampFinalized(FIXED_DATE);
        return response;
    }

}
