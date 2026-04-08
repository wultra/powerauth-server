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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import org.junit.jupiter.api.Test;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for {@link OperationServiceBehavior#isForbiddenAscii(String)}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class ForbiddenAsciiRegexPerformanceTest {

    private static final double THRESHOLD_NS = 1000.0; // 1 microsecond

    @Test
    void testRegexPerformance() throws Exception {
        final Options opt = new OptionsBuilder()
                .include(ForbiddenAsciiRegexBenchmark.class.getSimpleName())
                .forks(1)
                .warmupIterations(1)
                .measurementIterations(3)
                .build();

        final Collection<RunResult> results = new Runner(opt).run();

        for (RunResult result : results) {
            double score = result.getPrimaryResult().getScore();
            String inputParam = result.getParams().getParam("input");
            assertTrue(score < THRESHOLD_NS, 
                String.format("Regex performance is too slow for input '%s': %.2f ns (threshold: %.2f ns)", 
                    inputParam, score, THRESHOLD_NS));
        }
    }
}
