/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.server.service.model.response;

/**
 * Response object for activation layer 2 response.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer2Response {

    private String activationId;
    private String serverPublicKey;
    private String ctrData;

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get Base64 encoded server public key.
     * @return Server public key.
     */
    public String getServerPublicKey() {
        return serverPublicKey;
    }

    /**
     * Set Base64 encoded server public key.
     * @param serverPublicKey Server public key.
     */
    public void setServerPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    /**
     * Get Base64 encoded counter data.
     * @return Counter data.
     */
    public String getCtrData() {
        return ctrData;
    }

    /**
     * Set Base64 encoded counter data.
     * @param ctrData Counter data.
     */
    public void setCtrData(String ctrData) {
        this.ctrData = ctrData;
    }
}
