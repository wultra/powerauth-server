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

package com.wultra.security.powerauth.app.server.util;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Objects;
import java.util.concurrent.Callable;

/**
 * Utility class to check for a thrown exception or different output.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AssertionUtils {

    /**
     * Checks whether an exception is thrown while executing an action or the result is different.
     * @param exceptionClass Exception class.
     * @param action Action to execute.
     * @param expectedResult Expected action result.
     * @param <T> Result type.
     */
    public static <T> void assertThrowsOrNotEqual(Class<? extends Throwable> exceptionClass, Callable<T> action, T expectedResult) {
        boolean exceptionThrown = false;
        T result = null;
        try {
            result = action.call();
        } catch (Throwable t) {
            assertTrue(exceptionClass.isInstance(t));
            exceptionThrown = true;
        }
        final boolean different = !Objects.equals(expectedResult, result);
        assertTrue(exceptionThrown || different);
    }

}