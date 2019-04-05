/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.exceptions;

import org.springframework.ws.soap.SoapFault;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.server.endpoint.SoapFaultMappingExceptionResolver;

import javax.xml.namespace.QName;

/**
 * SOAP fault exception resolver for SOAP errors.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SoapFaultExceptionResolver extends SoapFaultMappingExceptionResolver {
    private static final QName ERROR_CODE = new QName("errorCode");
    private static final QName LOCALIZED_MESSAGE = new QName("localizedMessage");
    private static final QName CURRENT_RECOVERY_PUK_INDEX = new QName("currentRecoveryPukIndex");

    @Override
    protected void customizeFault(Object endpoint, Exception ex, SoapFault fault) {
        if (ex instanceof ActivationRecoveryException) {
            ActivationRecoveryException recoveryException = (ActivationRecoveryException) ex;
            SoapFaultDetail detail = fault.addFaultDetail();
            detail.addFaultDetailElement(ERROR_CODE).addText(recoveryException.getCode());
            detail.addFaultDetailElement(LOCALIZED_MESSAGE).addText(recoveryException.getLocalizedMessage());
            detail.addFaultDetailElement(CURRENT_RECOVERY_PUK_INDEX).addText(String.valueOf(recoveryException.getCurrentRecoveryPukIndex()));
        } else if (ex instanceof GenericServiceException) {
            GenericServiceException genericException = (GenericServiceException) ex;
            SoapFaultDetail detail = fault.addFaultDetail();
            detail.addFaultDetailElement(ERROR_CODE).addText(genericException.getCode());
            detail.addFaultDetailElement(LOCALIZED_MESSAGE).addText(genericException.getLocalizedMessage());
        }
    }
}
