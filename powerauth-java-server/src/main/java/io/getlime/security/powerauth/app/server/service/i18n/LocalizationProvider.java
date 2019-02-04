/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.i18n;

import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Service;

import java.util.Locale;

/**
 * Class responsible for providing localized error messages in case of
 * SOAP fault exceptions. Currently, only EN locale is provided with the
 * server.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class LocalizationProvider {

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("i18n/errors");
        source.setUseCodeAsDefaultMessage(true);
        return source;
    }

    public String getLocalizedErrorMessage(String code) {
        return this.getLocalizedErrorMessage(code, Locale.ENGLISH);
    }

    public String getLocalizedErrorMessage(String code, Locale locale) {
        return messageSource().getMessage("ServiceError." + code, null, locale);
    }

    public GenericServiceException buildExceptionForCode(String code) {
        return this.buildExceptionForCode(code, Locale.ENGLISH);
    }

    public GenericServiceException buildExceptionForCode(String code, Locale locale) {
        String message = this.getLocalizedErrorMessage(code);
        String localizedMessage = this.getLocalizedErrorMessage(code, locale);
        return new GenericServiceException(code, message, localizedMessage);
    }

}
