/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.server.service.util;

import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Utility class used for conversion between model data types.
 *
 * @author Petr Dvorak
 */
public class ModelUtil {

    /**
     * Convert between activation status repository and SOAP service enum.
     *
     * @param repositoryStatus Repository status representation.
     * @return SOAP service status representation.
     */
    public static io.getlime.security.powerauth.ActivationStatus toServiceStatus(
            ActivationStatus repositoryStatus) {
        switch (repositoryStatus) {
            case CREATED:
                return io.getlime.security.powerauth.ActivationStatus.CREATED;
            case OTP_USED:
                return io.getlime.security.powerauth.ActivationStatus.OTP_USED;
            case ACTIVE:
                return io.getlime.security.powerauth.ActivationStatus.ACTIVE;
            case BLOCKED:
                return io.getlime.security.powerauth.ActivationStatus.BLOCKED;
            case REMOVED:
                return io.getlime.security.powerauth.ActivationStatus.REMOVED;
        }
        return io.getlime.security.powerauth.ActivationStatus.REMOVED;
    }

    /**
     * Convert between Date and XMLGregorianCalendar.
     *
     * @param date Date instance
     * @return XMLGregorianCalendar instance
     * @throws DatatypeConfigurationException In case data conversion fails
     */
    public static XMLGregorianCalendar calendarWithDate(Date date) throws DatatypeConfigurationException {
        if (date == null) {
            return null;
        }
        GregorianCalendar c = new GregorianCalendar();
        c.setTime(date);
        XMLGregorianCalendar date2 = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
        return date2;
    }

    /**
     * Convert between Date and XMLGregorianCalendar.
     *
     * @param calendar XMLGregorianCalendar instance
     * @return Date instance
     * @throws DatatypeConfigurationException In case data conversion fails
     */
    public static Date dateWithCalendar(XMLGregorianCalendar calendar) throws DatatypeConfigurationException {
        if (calendar == null) {
            return null;
        }
        return calendar.toGregorianCalendar().getTime();
    }

}
