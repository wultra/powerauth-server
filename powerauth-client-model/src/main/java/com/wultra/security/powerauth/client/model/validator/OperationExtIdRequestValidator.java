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

package com.wultra.security.powerauth.client.model.validator;

import com.wultra.security.powerauth.client.model.request.OperationExtIdRequest;
import com.wultra.security.powerauth.client.model.request.OperationListForUserRequest;

/**
 * Validator for OperationExtIdRequest class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationExtIdRequestValidator {

    public static String validate(OperationExtIdRequest source) {
        if (source == null) {
            return "Operation lookup by external ID request must not be null";
        }
        if (source.getApplicationId() == null) {
            return "Application ID must not be null when requesting operation lookup by external ID";
        }
        if (source.getExternalId() == null) {
            return "External ID must not be null when requesting operation lookup by external ID";
        }
        if (source.getExternalId().isEmpty()) {
            return "External ID must not be empty when requesting operation lookup by external ID";
        }
        return null;
    }

}
