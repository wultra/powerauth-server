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

package io.getlime.security.powerauth.app.server.service.replay;

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.database.repository.UniqueValueRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.UniqueValueParam;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.*;

/**
 * Test cases for replay protection for various protocol versions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ReplayVerificationServiceTest {

    private DefaultReplayVerificationService verificationService;
    private ReplayPersistenceService inMemoryPersistence;

    @BeforeAll
    void setup() {
        final LocalizationProvider localizationProvider = mock(LocalizationProvider.class);
        final PowerAuthServiceConfiguration configuration = mock(PowerAuthServiceConfiguration.class);
        final UniqueValueRepository uniqueValueRepository = mock(UniqueValueRepository.class);

        when(configuration.getRequestExpiration()).thenReturn(Duration.ofSeconds(60));
        when(configuration.getRequestExpirationExtended()).thenReturn(Duration.ofMinutes(120));
        when(localizationProvider.buildExceptionForCode(any())).thenThrow(new RuntimeException());

        inMemoryPersistence = new ReplayPersistenceService(uniqueValueRepository, configuration) {
            private final Set<String> replayStore = new HashSet<>();

            @Override
            public boolean uniqueValueExists(String uniqueValue) {
                return replayStore.contains(uniqueValue);
            }

            @Override
            public boolean persistUniqueValue(UniqueValueType type, String uniqueValue) {
                return replayStore.add(uniqueValue);
            }
        };

        verificationService = new DefaultReplayVerificationService(inMemoryPersistence, localizationProvider, configuration);
    }

    @ParameterizedTest
    @MethodSource("provideTestCases")
    void testReplayValidation(TestCase tc) {
        try {
            final UniqueValueParam param = new UniqueValueParam();
            param.setUniqueValueType(tc.type);
            param.setApplicationKey(tc.applicationKey);
            param.setEphemeralPublicKey(tc.ephemeralKey);
            param.setNonce(tc.nonce);
            param.setIdentifier(tc.identifier);
            verificationService.checkAndPersistUniqueValue(tc.version, tc.timestamp, param);
            if (tc.shouldPass) {
                assertTrue(inMemoryPersistence.uniqueValueExists(tc.expectedUniqueValue), "Expected unique value not generated: " + tc.expectedUniqueValue);
            } else {
                fail("Expected failure for: " + tc);
            }
        } catch (RuntimeException | GenericServiceException e) {
            if (tc.shouldPass) {
                fail("Unexpected failure for: " + tc + " - " + e.getMessage());
            }
        }
    }

    static Stream<TestCase> provideTestCases() {
        Instant now = Instant.now();
        return Stream.of(
                // --- 3.0 ---
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-1", null, "bm9uY2U=", Date.from(now), true, "YXBwS2V5LTFub25jZXRva2VuLWlkLTE="),
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-1", null, "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-2", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-2", null, "bm9uY2U=", Date.from(now), true, "YXBwS2V5LTFub25jZXRva2VuLWlkLTI="),
                // For protocol version 3.0 ECIES replay attacks are not verified because of missing timestamps in requests

                // --- 3.1 ---
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-3", null, "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0ybm9uY2V0b2tlbi1pZC0z"),
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-3", null, "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-4", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-4", null, "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0ybm9uY2V0b2tlbi1pZC00"),
                // For protocol version 3.1 ECIES replay attacks are not verified because of missing timestamps in requests

                // --- 3.2 ---
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-5", null, "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0zbm9uY2V0b2tlbi1pZC01"),
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-6", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-7", null, "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0zbm9uY2V0b2tlbi1pZC03"),
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-7", null, "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.2", UniqueValueType.ECIES_APPLICATION_SCOPE, "YXBwLWtleS0z", null, "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0zZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZQ=="),
                new TestCase("3.2", UniqueValueType.ECIES_APPLICATION_SCOPE, "YXBwLWtleS0z", null, "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.2", UniqueValueType.ECIES_ACTIVATION_SCOPE, "YXBwLWtleS0z", "activation-id-5", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0zZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZWFjdGl2YXRpb24taWQtNQ=="),
                new TestCase("3.2", UniqueValueType.ECIES_ACTIVATION_SCOPE, "YXBwLWtleS0z", "activation-id-5", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.2", UniqueValueType.ECIES_ACTIVATION_SCOPE, "YXBwLWtleS0z", "activation-id-6", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0zZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZWFjdGl2YXRpb24taWQtNg=="),

                // --- 3.3 ---
                new TestCase("3.3", UniqueValueType.MAC_TOKEN, null, "token-id-8", null, "bm9uY2U=", Date.from(now), true, "bm9uY2V0b2tlbi1pZC04"),
                new TestCase("3.3", UniqueValueType.MAC_TOKEN, null, "token-id-8", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),
                new TestCase("3.3", UniqueValueType.MAC_TOKEN, null, "token-id-9", null, "bm9uY2U=", Date.from(now), true, "bm9uY2V0b2tlbi1pZC05"),
                new TestCase("3.3", UniqueValueType.MAC_TOKEN, null, "token-id-9", null, "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-1", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), true, "ZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZXRlbXAta2V5LWlkLTE="),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-1", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), false, null),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-2", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-2", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), true, "ZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZXRlbXAta2V5LWlkLTI="),

                // Timestamp range test cases
                // --- 3.0 Expiration: 120 min (7200s) ---
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-3001", null, "bm9uY2U=", Date.from(now.minusSeconds(7199)), true, "YXBwS2V5LTFub25jZXRva2VuLWlkLTMwMDE="),
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-3002", null, "bm9uY2U=", Date.from(now.minusSeconds(7201)), false, null),
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-3003", null, "bm9uY2U=", Date.from(now), true, "YXBwS2V5LTFub25jZXRva2VuLWlkLTMwMDM="),
                new TestCase("3.0", UniqueValueType.MAC_TOKEN, "YXBwS2V5LTE=", "token-id-3004", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),

                // --- 3.1 Expiration: 120 min (7200s) ---
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-3101", null, "bm9uY2U=", Date.from(now.minusSeconds(7199)), true, "YXBwLWtleS0ybm9uY2V0b2tlbi1pZC0zMTAx"),
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-3102", null, "bm9uY2U=", Date.from(now.minusSeconds(7201)), false, null),
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-3103", null, "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0ybm9uY2V0b2tlbi1pZC0zMTAz"),
                new TestCase("3.1", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0y", "token-id-3104", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),

                // --- 3.2 Expiration: 60s ---
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-3201", null, "bm9uY2U=", Date.from(now.minusSeconds(59)), true, "YXBwLWtleS0zbm9uY2V0b2tlbi1pZC0zMjAx"),
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-3202", null, "bm9uY2U=", Date.from(now.minusSeconds(61)), false, null),
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-3203", null, "bm9uY2U=", Date.from(now), true, "YXBwLWtleS0zbm9uY2V0b2tlbi1pZC0zMjAz"),
                new TestCase("3.2", UniqueValueType.MAC_TOKEN, "YXBwLWtleS0z", "token-id-3204", null, "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null),

                // --- 3.3 Expiration: 60s ---
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-3301", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now.minusSeconds(59)), true, "ZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZXRlbXAta2V5LWlkLTMzMDE="),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-3302", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now.minusSeconds(61)), false, null),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-3303", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now), true, "ZXBoZW1lcmFsLXB1YmxpYy1rZXlub25jZXRlbXAta2V5LWlkLTMzMDM="),
                new TestCase("3.3", UniqueValueType.ECIES_WITH_TEMPORARY_KEY, null, "temp-key-id-3304", "ZXBoZW1lcmFsLXB1YmxpYy1rZXk=", "bm9uY2U=", Date.from(now.plusSeconds(1)), false, null)
        );
    }

    public record TestCase(String version, UniqueValueType type, String applicationKey, String identifier, String ephemeralKey, String nonce, Date timestamp, boolean shouldPass, String expectedUniqueValue) {}

}
