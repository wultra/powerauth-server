/*
 * PowerAuth Server and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.database.model.entity;

import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

/**
 * Entity class for storing callback authentication credentials in database.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Getter
@Setter
public class CallbackUrlAuthentication implements Serializable {

    @Serial
    private static final long serialVersionUID = -8747094084020567435L;

    /**
     * Certificate authentication credentials object.
     */
    private Certificate certificate;

    /**
     * HTTP basic authentication credentials object.
     */
    private HttpBasic httpBasic;

    /**
     * OAuth2 credentials object.
     */
    private OAuth2 oAuth2;

    /**
     * Inner-class with certificate authentication credentials.
     */
    @Getter
    @Setter
    public static class Certificate implements Serializable {

        @Serial
        private static final long serialVersionUID = -3123397103510377094L;

        private boolean enabled;
        private boolean useCustomKeyStore;
        private String keyStoreLocation;
        private String keyStorePassword;
        private String keyAlias;
        private String keyPassword;
        private boolean useCustomTrustStore;
        private String trustStoreLocation;
        private String trustStorePassword;
    }

    /**
     * Inner-class with Basic HTTP authentication credentials.
     */
    @Getter
    @Setter
    public static class HttpBasic implements Serializable {

        @Serial
        private static final long serialVersionUID = 4449327538548490513L;

        private boolean enabled;
        private String username;
        private String password;
    }

    /**
     * OAuth2 credentials for client credentials flow.
     */
    @Getter
    @Setter
    public static class OAuth2 implements Serializable {

        @Serial
        private static final long serialVersionUID = 1131711931761161659L;

        private boolean enabled;
        private String tokenUri;
        private String clientId;
        private String clientSecret;
        private String scope;
    }

}
