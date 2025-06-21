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

package io.getlime.security.powerauth.app.server.service.model;

import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import lombok.Data;
import lombok.ToString;

/**
 * Parameters for unique value data checks in replay attack protection.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class UniqueValueParam {

    private String ephemeralPublicKey;
    @ToString.Exclude
    private String nonce;
    private String identifier;
    private UniqueValueType uniqueValueType;

}
