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

import java.io.Serializable;

/**
 * Entity class for storing callback authentication credentials in database.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class CallbackUrlAuthenticationEntity implements Serializable {

    private static final long serialVersionUID = -8747094084020567435L;

    private Certificate certificate;
    private HttpBasic httpBasic;

    /**
     * Get certificate authentication credentials object.
     * @return Certificate authentication credentials.
     */
    public Certificate getCertificate() {
        return certificate;
    }

    /**
     * Set certificate authentication credentials object.
     * @param certificate Certificate authentication credentials.
     */
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Get HTTP basic authentication credentials object.
     * @return HTTP basic authentication credentials.
     */
    public HttpBasic getHttpBasic() {
        return httpBasic;
    }

    /**
     * Set HTTP basic authentication credentials object.
     * @param httpBasic HTTP basic authentication credentials.
     */
    public void setHttpBasic(HttpBasic httpBasic) {
        this.httpBasic = httpBasic;
    }

    /**
     * Inner-class with certificate authentication credentials.
     */
    public static class Certificate implements Serializable {

        private static final long serialVersionUID = -3123397103510377094L;

        protected boolean enabled;
        protected boolean useCustomKeyStore;
        protected String keyStoreLocation;
        protected String keyStorePassword;
        protected String keyAlias;
        protected String keyPassword;
        protected boolean useCustomTrustStore;
        protected String trustStoreLocation;
        protected String trustStorePassword;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isUseCustomKeyStore() {
            return useCustomKeyStore;
        }

        public void setUseCustomKeyStore(boolean useCustomKeyStore) {
            this.useCustomKeyStore = useCustomKeyStore;
        }

        public String getKeyStoreLocation() {
            return keyStoreLocation;
        }

        public void setKeyStoreLocation(String keyStoreLocation) {
            this.keyStoreLocation = keyStoreLocation;
        }

        public String getKeyStorePassword() {
            return keyStorePassword;
        }

        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        public String getKeyAlias() {
            return keyAlias;
        }

        public void setKeyAlias(String keyAlias) {
            this.keyAlias = keyAlias;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }

        public boolean isUseCustomTrustStore() {
            return useCustomTrustStore;
        }

        public void setUseCustomTrustStore(boolean useCustomTrustStore) {
            this.useCustomTrustStore = useCustomTrustStore;
        }

        public String getTrustStoreLocation() {
            return trustStoreLocation;
        }

        public void setTrustStoreLocation(String trustStoreLocation) {
            this.trustStoreLocation = trustStoreLocation;
        }

        public String getTrustStorePassword() {
            return trustStorePassword;
        }

        public void setTrustStorePassword(String trustStorePassword) {
            this.trustStorePassword = trustStorePassword;
        }
    }

    /**
     * Inner-class with Basic HTTP authentication credentials.
     */
    public static class HttpBasic implements Serializable {

        private static final long serialVersionUID = 4449327538548490513L;

        protected boolean enabled;
        protected String username;
        protected String password;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

}
