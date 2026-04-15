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
 *
 */
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeout;

/**
 * Test class for {@link OperationServiceBehavior#isForbiddenAscii(String)}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class ForbiddenAsciiRegexPerformanceTest {

    /**
     * It should finish under 10 milliseconds if warmed up.
     * The invalid code with {@code .*} took more than 200 ms.
     */
    @Test
    void testRegexPerformance() {
        final String input = generateString();

        // Warmup to avoid measuring initialization cost
        assertFalse(OperationServiceBehavior.isForbiddenAscii(input));

        // Assert for regexp performance
        assertTimeout(Duration.ofMillis(10), () -> {
            OperationServiceBehavior.isForbiddenAscii(input);
        }, "Regex performance is too slow for input");
    }

    private static String generateString() {
        return "a".repeat(10_000);
    }
}
