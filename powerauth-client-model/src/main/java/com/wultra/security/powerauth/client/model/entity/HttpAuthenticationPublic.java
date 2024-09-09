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
package com.wultra.security.powerauth.client.model.entity;

import lombok.Data;

/**
 * HTTP authentication class that is intended for public usage. It does not contain any
 * sensitive data, such as passwords.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class HttpAuthenticationPublic {

    private Certificate certificate = new Certificate();
    private HttpBasic httpBasic = new HttpBasic();
    private OAuth2 oAuth2 = new OAuth2();

    @Data
    public static class Certificate {
        private boolean enabled;
        private boolean useCustomKeyStore;
        private String keyStoreLocation;
        private boolean keyStorePasswordSet;
        private String keyAlias;
        private boolean keyPasswordSet;
        private boolean useCustomTrustStore;
        private String trustStoreLocation;
        private boolean trustStorePasswordSet;
    }

    @Data
    public static class HttpBasic {
        private boolean enabled;
        private String username;
        private boolean passwordSet;
    }

    @Data
    public static class OAuth2 {
        private boolean enabled;
        private String tokenUri;
        private String clientId;
        private boolean clientSecretSet;
        private String scope;
    }

}
