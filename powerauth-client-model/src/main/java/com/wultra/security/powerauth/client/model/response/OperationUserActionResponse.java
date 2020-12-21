/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.response;

/**
 * Response object for operation approval.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationUserActionResponse {

    private String result;
    private OperationDetailResponse operation;

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public OperationDetailResponse getOperation() {
        return operation;
    }

    public void setOperation(OperationDetailResponse operation) {
        this.operation = operation;
    }
}
