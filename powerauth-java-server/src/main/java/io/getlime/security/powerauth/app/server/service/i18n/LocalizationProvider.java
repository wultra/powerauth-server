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

import io.getlime.security.powerauth.app.server.service.exceptions.ActivationRecoveryException;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.exceptions.RollbackingServiceException;
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

    /**
     * Create message source bean.
     * @return Message source bean.
     */
    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("i18n/errors");
        source.setUseCodeAsDefaultMessage(true);
        return source;
    }

    /**
     * Get localized error message for given error code in English.
     * @param code Error code.
     * @return Localized error message.
     */
    public String getLocalizedErrorMessage(String code) {
        return this.getLocalizedErrorMessage(code, Locale.ENGLISH);
    }

    /**
     * Get localized error message for given error code and locale.
     * @param code Error code.
     * @param locale Locale.
     * @return Localized error message.
     */
    public String getLocalizedErrorMessage(String code, Locale locale) {
        return messageSource().getMessage("ServiceError." + code, null, locale);
    }

    /**
     * Build exception that doesn't cause transaction rollback for given error code in English.
     * @param code Error code.
     * @return Generic service exception.
     */
    public GenericServiceException buildExceptionForCode(String code) {
        return this.buildExceptionForCode(code, Locale.ENGLISH);
    }

    /**
     * Build exception that doesn't cause transaction rollback for given error code and locale.
     * @param code Error code.
     * @param locale Locale.
     * @return Generic service exception.
     */
    public GenericServiceException buildExceptionForCode(String code, Locale locale) {
        String message = getLocalizedErrorMessage(code);
        String localizedMessage = getLocalizedErrorMessage(code, locale);
        return new GenericServiceException(code, message, localizedMessage);
    }

    /**
     * Build rollbacking exception for given error code in English.
     * @param code Error code.
     * @return Rollbacking service exception.
     */
    public RollbackingServiceException buildRollbackingExceptionForCode(String code) {
        return this.buildRollbackingExceptionForCode(code, Locale.ENGLISH);
    }

    /**
     * Build rollbacking exception for given error code and locale.
     * @param code Error code.
     * @param locale Locale.
     * @return Rollbacking service exception.
     */
    public RollbackingServiceException buildRollbackingExceptionForCode(String code, Locale locale) {
        String message = getLocalizedErrorMessage(code);
        String localizedMessage = getLocalizedErrorMessage(code, locale);
        return new RollbackingServiceException(code, message, localizedMessage);
    }

    /**
     * Build activation recovery exception for given error code in English with current recovery PUK index parameter.
     * @param code Error code.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     * @return Activation recovery exception.
     */
    public ActivationRecoveryException buildActivationRecoveryExceptionForCode(String code, int currentRecoveryPukIndex) {
        return this.buildActivationRecoveryExceptionForCode(code, Locale.ENGLISH, currentRecoveryPukIndex);
    }

    /**
     * Build activation recovery exception for given error code and locale with current recovery PUK index parameter.
     * @param code Error code.
     * @param locale Locale.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     * @return Activation recovery exception.
     */
    public ActivationRecoveryException buildActivationRecoveryExceptionForCode(String code, Locale locale, int currentRecoveryPukIndex) {
        String message = getLocalizedErrorMessage(code);
        String localizedMessage = getLocalizedErrorMessage(code, locale);
        return new ActivationRecoveryException(code, message, localizedMessage, currentRecoveryPukIndex);
    }

}
