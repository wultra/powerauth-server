/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.entity.ErrorInfo;
import com.wultra.security.powerauth.client.model.response.GetErrorCodeListResponse;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class ErrorCodeBehavior {

    private final LocalizationProvider localizationProvider;

    @Autowired
    public ErrorCodeBehavior(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    /**
     * Return error code list
     * @return Error code list
     */
    public GetErrorCodeListResponse getErrorCodeList() {
        final Locale locale = Locale.ENGLISH;
        final GetErrorCodeListResponse response = new GetErrorCodeListResponse();
        final List<String> errorCodeList = ServiceError.allCodes();
        for (String errorCode : errorCodeList) {
            final ErrorInfo error = new ErrorInfo();
            error.setCode(errorCode);
            error.setValue(localizationProvider.getLocalizedErrorMessage(errorCode, locale));
            response.getErrors().add(error);
        }
        return response;
    }

}
