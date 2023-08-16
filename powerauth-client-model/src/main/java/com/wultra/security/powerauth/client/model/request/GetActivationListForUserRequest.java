/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.request;

import com.wultra.security.powerauth.client.model.enumeration.Protocols;
import jakarta.validation.constraints.Min;
import lombok.Data;

import java.util.Set;

/**
 * Model class representing request for activation list for a given user.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class GetActivationListForUserRequest {

    private String userId;
    private String applicationId;
    private Set<Protocols> protocols = Set.of(Protocols.FIDO2, Protocols.POWERAUTH);
    @Min(0)
    private Integer pageNumber;
    @Min(1)
    private Integer pageSize;

}
