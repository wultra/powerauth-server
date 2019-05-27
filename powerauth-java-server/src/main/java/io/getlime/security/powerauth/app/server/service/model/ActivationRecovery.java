/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
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
package io.getlime.security.powerauth.app.server.service.model;

/**
 * Activation recovery model class for recovery code and PUK.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ActivationRecovery {

    private String recoveryCode;
    private String puk;

    /**
     * Default constuctor.
     */
    public ActivationRecovery() {
    }

    /**
     * Constructor with recovery code and PUK.
     * @param recoveryCode Recovery code.
     * @param puk Recovery PUK.
     */
    public ActivationRecovery(String recoveryCode, String puk) {
        this.recoveryCode = recoveryCode;
        this.puk = puk;
    }

    /**
     * Get recovery code.
     * @return Recovery code.
     */
    public String getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Set recovery code.
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }

    /**
     * Get recovery PUK.
     * @return Recovery PUK.
     */
    public String getPuk() {
        return puk;
    }

    /**
     * Set recovery PUK.
     * @param puk Recovery PUK.
     */
    public void setPuk(String puk) {
        this.puk = puk;
    }
}