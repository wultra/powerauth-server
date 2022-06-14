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

import com.wultra.security.powerauth.client.model.request.OperationApproveRequest;
import org.springframework.util.StringUtils;

/**
 * Validator for OperationApproveRequest class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationApproveRequestValidator {

    public static String validate(OperationApproveRequest source) {
        if (source == null) {
            return "Operation approve request must not be null";
        }
        if (!StringUtils.hasText(source.getApplicationId())) {
            return "Application ID must not be null or empty when creating operation";
        }
        if (source.getOperationId() == null) {
            return "Operation ID must not be null when approving operation";
        }
        if (source.getOperationId().isEmpty()) {
            return "Operation ID must not be empty when approving operation";
        }
        if (source.getUserId() == null) {
            return "User ID must not be null when approving operation";
        }
        if (source.getUserId().isEmpty()) {
            return "User ID must not be empty when approving operation";
        }
        if (source.getData() == null) {
            return "Data must not be null when approving operation";
        }
        if (source.getData().isEmpty()) {
            return "Data must not be empty when approving operation";
        }
        if (source.getSignatureType() == null) {
            return "Signature type must not be empty when approving operation";
        }
        return null;
    }

}
