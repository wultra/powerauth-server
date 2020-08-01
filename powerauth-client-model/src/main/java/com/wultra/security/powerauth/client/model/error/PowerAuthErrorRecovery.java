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
package com.wultra.security.powerauth.client.model.error;

/**
 * Class representing a PowerAuth recovery error.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthErrorRecovery extends PowerAuthError {

    private int currentRecoveryPukIndex;

    /**
     * Default constructor.
     */
    public PowerAuthErrorRecovery() {
    }

    /**
     * Current recovery PUK index.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     */
    public PowerAuthErrorRecovery(int currentRecoveryPukIndex) {
        this.currentRecoveryPukIndex = currentRecoveryPukIndex;
    }

    /**
     * Get current recovery PUK index.
     * @return Current recovery PUK index.
     */
    public int getCurrentRecoveryPukIndex() {
        return currentRecoveryPukIndex;
    }

    /**
     * Set current recovery PUK index.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     */
    public void setCurrentRecoveryPukIndex(int currentRecoveryPukIndex) {
        this.currentRecoveryPukIndex = currentRecoveryPukIndex;
    }
}
