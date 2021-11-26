/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
package com.wultra.security.powerauth.client.model.auth;

import lombok.Data;

/**
 * Model class for HTTP request authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class HttpAuthentication {

    private CertificateAuth certificate;
    private HttpBasicAuth httpBasic;

    @Data
    public static class CertificateAuth {
        private boolean enabled = false;
        private boolean useCustomKeyStore = false;
        private String keyStoreLocation;
        private String keyStorePassword;
        private String keyAlias;
        private String keyPassword;
        private boolean useCustomTrustStore = false;
        private String trustStoreLocation;
        private String trustStorePassword;
    }

    @Data
    public static class HttpBasicAuth {
        private boolean enabled = false;
        private String username;
        private String password;
    }

}