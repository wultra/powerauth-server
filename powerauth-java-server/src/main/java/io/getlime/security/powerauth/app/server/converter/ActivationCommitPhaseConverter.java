/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.converter;

import com.wultra.security.powerauth.client.model.enumeration.CommitPhase;

/**
 * Converter class between {@link CommitPhase} and
 * {@link io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase}.
 */
public class ActivationCommitPhaseConverter {

    /**
     * Convert activation commit phase from database model to web service model.
     *
     * @param commitPhase Commit phase.
     * @return Converted activation commit phase.
     */
    public CommitPhase convertFrom(io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase commitPhase) {
        if (commitPhase == null) {
            return CommitPhase.ON_COMMIT;
        }
        return switch (commitPhase) {
            case ON_COMMIT -> CommitPhase.ON_COMMIT;
            case ON_KEY_EXCHANGE -> CommitPhase.ON_KEY_EXCHANGE;
        };
    }

    /**
     * Convert commit phase from web service model to database model.
     * @param commitPhase Activation commit phase.
     * @return Converted activation commit phase.
     */
    public io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase convertTo(CommitPhase commitPhase) {
        if (commitPhase == null) {
            return io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase.ON_COMMIT;
        }
            return switch (commitPhase) {
                case ON_COMMIT -> io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase.ON_COMMIT;
                case ON_KEY_EXCHANGE -> io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase.ON_KEY_EXCHANGE;
            };
    }
}