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

package io.getlime.security.powerauth.app.server.database.model.converter;

import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationOtpValidation;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

/**
 * Converter between {@link CommitPhase} enumeration and integer values.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Converter
@Component
public class ActivationCommitPhaseConverter implements AttributeConverter<CommitPhase, Integer> {

    /**
     * Convert {@link ActivationOtpValidation} enum into integer value
     * @param commitPhase Enumeration to convert.
     * @return Integer representation of {@link CommitPhase} enumeration.
     */
    @Override
    public Integer convertToDatabaseColumn(CommitPhase commitPhase) {
        if (commitPhase == null) {
            // For compatibility with old data
            return 0;
        }
        return switch (commitPhase) {
            case ON_COMMIT -> 0;
            case ON_KEY_EXCHANGE -> 1;
        };
    }

    /**
     * Convert integer value into {@link CommitPhase} enumeration.
     * @param value Integer value to convert.
     * @return {@link CommitPhase} enumeration.
     */
    @Override
    public CommitPhase convertToEntityAttribute(Integer value) {
        if (value == null) {
            // For compatibility with old data
            return CommitPhase.ON_COMMIT;
        }
        return switch (value) {
            case 0 -> CommitPhase.ON_COMMIT;
            case 1 -> CommitPhase.ON_KEY_EXCHANGE;
            default -> CommitPhase.ON_COMMIT;
        };
    }

}
