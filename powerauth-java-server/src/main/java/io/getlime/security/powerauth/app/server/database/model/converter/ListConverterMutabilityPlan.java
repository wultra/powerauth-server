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

import org.hibernate.SharedSessionContract;
import org.hibernate.type.descriptor.java.MutabilityPlan;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * // TODO (racansky, 2023-04-17, https://hibernate.atlassian.net/browse/HHH-16081) workaround for non working-dirty checking
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public class ListConverterMutabilityPlan implements MutabilityPlan<List<String>> {

    @Override
    public boolean isMutable() {
        return true;
    }

    @Override
    public List<String> deepCopy(List<String> value) {
        return new ArrayList<>(value);
    }

    @Override
    public Serializable disassemble(List<String> value, SharedSessionContract session) {
        return new ArrayList<>(value);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> assemble(Serializable cached, SharedSessionContract session) {
        return new ArrayList<>((List<String>)cached);
    }
}
