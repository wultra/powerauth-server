/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.powerauth.soap.adapter;

import java.time.ZoneId;
import java.util.TimeZone;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class ZoneRule extends TestWatcher {

    private TimeZone systemDefault;
    private final ZoneId zone;

    ZoneRule(ZoneId zone) {
        this.zone = zone;
    }

    @Override
    protected void starting(Description description) {
        systemDefault = TimeZone.getDefault();
        super.starting(description);

        TimeZone.setDefault(TimeZone.getTimeZone(zone));
    }

    @Override
    protected void finished(Description description) {
        super.finished(description);
        TimeZone.setDefault(systemDefault);
    }
}