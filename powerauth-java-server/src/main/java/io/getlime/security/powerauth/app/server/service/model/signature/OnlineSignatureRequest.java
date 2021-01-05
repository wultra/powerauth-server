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
package io.getlime.security.powerauth.app.server.service.model.signature;

import com.wultra.security.powerauth.client.v3.SignatureType;

/**
 * Request to verify online signature.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class OnlineSignatureRequest {

    private SignatureData signatureData;
    private SignatureType signatureType;

    /**
     * Default constructor.
     */
    public OnlineSignatureRequest() {
    }

    /**
     * Online signature request constructur.
     * @param signatureData Data related to the signature.
     * @param signatureType Signature type to use during verification of signature.
     */
    public OnlineSignatureRequest(SignatureData signatureData, SignatureType signatureType) {
        this.signatureData = signatureData;
        this.signatureType = signatureType;
    }

    /**
     * Get data related to the signature.
     * @return Data related to the signature
     */
    public SignatureData getSignatureData() {
        return signatureData;
    }

    /**
     * Get signature type to use during verification of signature.
     * @return Signature type to use during verification.
     */
    public SignatureType getSignatureType() {
        return signatureType;
    }

}
