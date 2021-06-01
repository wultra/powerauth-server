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
package io.getlime.security.powerauth.app.server.service.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Class for representing a SOAP service errors. It has static string fields
 * for all possible error codes and list that registers the error code.
 * The {@link io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider}
 * class is then used for looking up the displayable error message.
 *
 * @author Petr Dvorak, petr@wultra.com
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
     * Too many failed attempts to generate activation code.
     */
    public static final String UNABLE_TO_GENERATE_ACTIVATION_CODE = "ERR0006";

    /**
     * This activation is already expired.
     */
    public static final String ACTIVATION_EXPIRED = "ERR0007";

    /**
     * Incorrect activation state.
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
     *
     * The error code is obsolete, because the error is handled using regular response instead of an exception.
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
     * Token was not successfully generated.
     */
    public static final String UNABLE_TO_GENERATE_TOKEN = "ERR0019";

    /**
     * Master DB encryption key is not configured.
     */
    public static final String MISSING_MASTER_DB_ENCRYPTION_KEY = "ERR0020";

    /**
     * Unsupported encryption mode.
     */
    public static final String UNSUPPORTED_ENCRYPTION_MODE = "ERR0021";

    /**
     * Generic cryptography error.
     */
    public static final String GENERIC_CRYPTOGRAPHY_ERROR = "ERR0022";

    /**
     * Cryptography provider is initialized incorrectly.
     */
    public static final String INVALID_CRYPTO_PROVIDER = "ERR0023";

    /**
     * Invalid request error.
     */
    public static final String INVALID_REQUEST = "ERR0024";

    /**
     * Could not generate recovery code because a valid recovery code already exists.
     */
    public static final String RECOVERY_CODE_ALREADY_EXISTS = "ERR0025";

    /**
     * Too many failed attempts to generate recovery code.
     */
    public static final String UNABLE_TO_GENERATE_RECOVERY_CODE = "ERR0026";

    /**
     * Recovery code was not found.
     */
    public static final String RECOVERY_CODE_NOT_FOUND = "ERR0027";

    /**
     * Invalid recovery code.
     */
    public static final String INVALID_RECOVERY_CODE = "ERR0028";

    /**
     * Recovery code configuration is missing or incomplete.
     */
    public static final String INVALID_RECOVERY_CONFIGURATION = "ERR0029";

    /**
     * Token timestamp is too old.
     */
    public static final String TOKEN_TIMESTAMP_TOO_OLD = "ERR0030";

    /**
     * Activation OTP doesn't match value stored in database, or the OTP value is provided for the wrong validation mode.
     */
    public static final String INVALID_ACTIVATION_OTP = "ERR0031";

    /**
     * Activation OTP operation is performed for the wrong validation mode.
     */
    public static final String INVALID_ACTIVATION_OTP_MODE = "ERR0032";

    /**
     * Operation template cannot be found.
     */
    public static final String OPERATION_TEMPLATE_NOT_FOUND = "ERR0033";

    /**
     * Operation cannot be found.
     */
    public static final String OPERATION_NOT_FOUND = "ERR0034";

    /**
     * Operation ID cannot generated.
     */
    public static final String UNABLE_TO_GENERATE_OPERATION_ID = "ERR0035";

    /**
     * Operation is in invalid state for requested change.
     */
    public static final String OPERATION_INVALID_STATE = "ERR0036";

    /**
     * Operation cannot be approved.
     */
    public static final String OPERATION_APPROVE_FAILURE = "ERR0037";

    /**
     * Operation cannot be approved.
     */
    public static final String OPERATION_REJECT_FAILURE = "ERR0038";

    /**
     * Operation template already exists.
     */
    public static final String OPERATION_TEMPLATE_ALREADY_EXISTS = "ERR0039";

    /**
     * Activation cannot be created with the specified properties.
     */
    public static final String ACTIVATION_CREATE_FAILED = "ERR0040";

    /**
     * Operation related error occurred.
     */
    public static final String OPERATION_ERROR = "ERR0041";

    /**
     * Operation template related error occurred.
     */
    public static final String OPERATION_TEMPLATE_ERROR = "ERR0042";


    public static List<String> allCodes() {
        List<String> list = new ArrayList<>(42);
        list.add(UNKNOWN_ERROR);
        list.add(NO_USER_ID);
        list.add(NO_APPLICATION_ID);
        list.add(NO_MASTER_SERVER_KEYPAIR);
        list.add(INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        list.add(UNABLE_TO_GENERATE_ACTIVATION_ID);
        list.add(UNABLE_TO_GENERATE_ACTIVATION_CODE);
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
        list.add(MISSING_MASTER_DB_ENCRYPTION_KEY);
        list.add(UNSUPPORTED_ENCRYPTION_MODE);
        list.add(GENERIC_CRYPTOGRAPHY_ERROR);
        list.add(INVALID_CRYPTO_PROVIDER);
        list.add(INVALID_REQUEST);
        list.add(RECOVERY_CODE_ALREADY_EXISTS);
        list.add(UNABLE_TO_GENERATE_RECOVERY_CODE);
        list.add(RECOVERY_CODE_NOT_FOUND);
        list.add(INVALID_RECOVERY_CODE);
        list.add(INVALID_RECOVERY_CONFIGURATION);
        list.add(TOKEN_TIMESTAMP_TOO_OLD);
        list.add(INVALID_ACTIVATION_OTP);
        list.add(INVALID_ACTIVATION_OTP_MODE);
        list.add(OPERATION_TEMPLATE_NOT_FOUND);
        list.add(OPERATION_NOT_FOUND);
        list.add(UNABLE_TO_GENERATE_OPERATION_ID);
        list.add(OPERATION_INVALID_STATE);
        list.add(OPERATION_APPROVE_FAILURE);
        list.add(OPERATION_REJECT_FAILURE);
        list.add(OPERATION_TEMPLATE_ALREADY_EXISTS);
        list.add(ACTIVATION_CREATE_FAILED);
        list.add(OPERATION_ERROR);
        list.add(OPERATION_TEMPLATE_ERROR);
        return list;
    }

}
