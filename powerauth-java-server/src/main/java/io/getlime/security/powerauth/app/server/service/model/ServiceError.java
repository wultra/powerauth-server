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

package io.getlime.security.powerauth.app.server.service.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Class for representing a SOAP service errors. It has static string fields
 * for all possible error codes and list that registers the error code.
 * The {@link io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider}
 * class is then used for looking up the displayable error message.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class ServiceError {

    /**
     * Unknown error occurred.
     */
    public static final String UNKNOWN_ERROR = "ERR0000";

    /**
     * No user ID was set.
     */
    public static final String NO_USER_ID = "ERR0001";

    /**
     * No application ID was set.
     */
    public static final String NO_APPLICATION_ID = "ERR0002";

    /**
     * No master server key pair configured in database.
     */
    public static final String NO_MASTER_SERVER_KEYPAIR = "ERR0003";

    /**
     * Master server key pair contains private key in incorrect format.
     */
    public static final String INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE = "ERR0004";

    /**
     * Too many failed attempts to generate activation ID.
     */
    public static final String UNABLE_TO_GENERATE_ACTIVATION_ID = "ERR0005";

    /**
     * Too many failed attempts to generate short activation ID.
     */
    public static final String UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID = "ERR0006";

    /**
     * This activation is already expired.
     */
    public static final String ACTIVATION_EXPIRED = "ERR0007";

    /**
     * Only activations in OTP_USED state can be committed.
     */
    public static final String ACTIVATION_INCORRECT_STATE = "ERR0008";

    /**
     * Activation with given activation ID was not found.
     */
    public static final String ACTIVATION_NOT_FOUND = "ERR0009";

    /**
     * Key with invalid format was provided.
     */
    public static final String INVALID_KEY_FORMAT = "ERR0010";

    /**
     * Invalid input parameter format.
     */
    public static final String INVALID_INPUT_FORMAT = "ERR0011";

    /**
     * Invalid Signature Provided.
     */
    public static final String INVALID_SIGNATURE = "ERR0012";

    /**
     * Unable to compute signature.
     */
    public static final String UNABLE_TO_COMPUTE_SIGNATURE = "ERR0013";

    /**
     * Invalid URL format.
     */
    public static final String INVALID_URL_FORMAT = "ERR0014";

    /**
     * Application or application version does not exist.
     */
    public static final String INVALID_APPLICATION = "ERR0015";

    /**
     * Token with given token ID does not exist.
     */
    public static final String INVALID_TOKEN = "ERR0016";

    /**
     * Data encryption failed.
     */
    public static final String ENCRYPTION_FAILED = "ERR0017";

    /**
     * Data decryption failed.
     */
    public static final String DECRYPTION_FAILED = "ERR0018";

    /**
     * Token was not successfully generated
     */
    public static final String UNABLE_TO_GENERATE_TOKEN = "ERR0019";

    public static List<String> allCodes() {
        List<String> list = new ArrayList<>(20);
        list.add(UNKNOWN_ERROR);
        list.add(NO_USER_ID);
        list.add(NO_APPLICATION_ID);
        list.add(NO_MASTER_SERVER_KEYPAIR);
        list.add(INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        list.add(UNABLE_TO_GENERATE_ACTIVATION_ID);
        list.add(UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID);
        list.add(ACTIVATION_EXPIRED);
        list.add(ACTIVATION_INCORRECT_STATE);
        list.add(ACTIVATION_NOT_FOUND);
        list.add(INVALID_KEY_FORMAT);
        list.add(INVALID_INPUT_FORMAT);
        list.add(INVALID_SIGNATURE);
        list.add(UNABLE_TO_COMPUTE_SIGNATURE);
        list.add(INVALID_URL_FORMAT);
        list.add(INVALID_APPLICATION);
        list.add(INVALID_TOKEN);
        list.add(ENCRYPTION_FAILED);
        list.add(DECRYPTION_FAILED);
        list.add(UNABLE_TO_GENERATE_TOKEN);
        return list;
    }

}
