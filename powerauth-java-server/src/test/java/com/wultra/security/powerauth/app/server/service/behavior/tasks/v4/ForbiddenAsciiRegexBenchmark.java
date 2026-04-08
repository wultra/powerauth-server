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

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

/**
 * Benchmark class for {@link OperationServiceBehavior#isForbiddenAscii}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Fork(1)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 5, time = 1)
public class ForbiddenAsciiRegexBenchmark {

    @Param({
            "Short normal string",
            "String with \n line feed which is allowed",
            "String with \t tab which is forbidden",
            "Very long string without any forbidden characters....................................................................................................",
            "Very long string with forbidden character at the end............................................................................................\u0001"
    })
    private String input;

    @Benchmark
    public boolean testRegex() {
        return OperationServiceBehavior.isForbiddenAscii(input);
    }

    public static void main(String[] args) throws RunnerException {
        final Options opt = new OptionsBuilder()
                .include(ForbiddenAsciiRegexBenchmark.class.getSimpleName())
                .build();

        new Runner(opt).run();
    }
}
