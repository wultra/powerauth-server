/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.database.model.converter;

import org.hibernate.type.descriptor.java.MutableMutabilityPlan;

import java.util.HashMap;
import java.util.Map;

/**
 * Specialization of {@link MutableMutabilityPlan} for {@code Map<String, String>}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
// TODO (racansky, 2023-04-17, https://hibernate.atlassian.net/browse/HHH-16081) workaround for non working-dirty checking
public class MapConverterMutabilityPlan extends MutableMutabilityPlan<Map<String, String>> {

    @Override
    public Map<String, String> deepCopyNotNull(Map<String, String> value) {
        return new HashMap<>(value);
    }
}
