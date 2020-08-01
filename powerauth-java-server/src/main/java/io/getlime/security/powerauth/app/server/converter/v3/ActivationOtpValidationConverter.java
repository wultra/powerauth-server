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

package io.getlime.security.powerauth.app.server.converter.v3;

/**
 * Converter class between {@link com.wultra.security.powerauth.client.v3.ActivationOtpValidation} and
 * {@link io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation}.
 */
public class ActivationOtpValidationConverter {

    /**
     * Convert activation OTP validation from database model to web service model.
     *
     * @param otpValidation Activation OTP validation mode.
     * @return Converted activation OTP validation mode.
     */
    public com.wultra.security.powerauth.client.v3.ActivationOtpValidation convertFrom(io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation otpValidation) {
        if (otpValidation != null) {
            switch (otpValidation) {
                case NONE:
                    return com.wultra.security.powerauth.client.v3.ActivationOtpValidation.NONE;
                case ON_COMMIT:
                    return com.wultra.security.powerauth.client.v3.ActivationOtpValidation.ON_COMMIT;
                case ON_KEY_EXCHANGE:
                    return com.wultra.security.powerauth.client.v3.ActivationOtpValidation.ON_KEY_EXCHANGE;
            }
        }
        return com.wultra.security.powerauth.client.v3.ActivationOtpValidation.NONE;
    }

    /**
     * Convert activation OTP validation from web service model to database model.
     * @param otpValidation Activation OTP validation mode.
     * @return Converted activation OTP validation mode.
     */
    public io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation convertTo(com.wultra.security.powerauth.client.v3.ActivationOtpValidation otpValidation) {
        if (otpValidation != null) {
            switch (otpValidation) {
                case NONE:
                    return io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation.NONE;
                case ON_COMMIT:
                    return io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation.ON_COMMIT;
                case ON_KEY_EXCHANGE:
                    return io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation.ON_KEY_EXCHANGE;
            }
        }
        return io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation.NONE;
    }
}