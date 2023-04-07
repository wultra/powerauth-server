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

import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPublic;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthenticationEntity;

/**
 * Converter of private to public HTTP authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class CallbackAuthenticationPublicConverter {

    /**
     * Convert private HTTP authentication to public HTTP authentication.
     * @param source Private HTTP authentication.
     * @return Public HTTP authentication.
     */
    public HttpAuthenticationPublic toPublic(CallbackUrlAuthenticationEntity source) {
        final HttpAuthenticationPublic destination = new HttpAuthenticationPublic();
        if (source == null) {
            return destination;
        }
        final CallbackUrlAuthenticationEntity.HttpBasic httpBasicPrivate = source.getHttpBasic();
        if (httpBasicPrivate != null) {
            final HttpAuthenticationPublic.HttpBasic httpBasicPublic = new HttpAuthenticationPublic.HttpBasic();
            httpBasicPublic.setEnabled(httpBasicPrivate.isEnabled());
            httpBasicPublic.setUsername(httpBasicPrivate.getUsername());
            httpBasicPublic.setPasswordSet(httpBasicPrivate.getPassword() != null && !httpBasicPrivate.getPassword().isEmpty());
            destination.setHttpBasic(httpBasicPublic);
        }
        final CallbackUrlAuthenticationEntity.Certificate certificatePrivate = source.getCertificate();
        if (certificatePrivate != null) {
            final HttpAuthenticationPublic.Certificate certificatePublic = new HttpAuthenticationPublic.Certificate();
            certificatePublic.setEnabled(certificatePrivate.isEnabled());
            certificatePublic.setUseCustomKeyStore(certificatePrivate.isUseCustomKeyStore());
            certificatePublic.setKeyStoreLocation(certificatePrivate.getKeyStoreLocation());
            certificatePublic.setKeyStorePasswordSet(certificatePrivate.getKeyStorePassword() != null && !certificatePrivate.getKeyStorePassword().isEmpty());
            certificatePublic.setKeyAlias(certificatePrivate.getKeyAlias());
            certificatePublic.setKeyPasswordSet(certificatePrivate.getKeyPassword() != null && !certificatePrivate.getKeyPassword().isEmpty());
            certificatePublic.setUseCustomTrustStore(certificatePrivate.isUseCustomTrustStore());
            certificatePublic.setTrustStoreLocation(certificatePrivate.getTrustStoreLocation());
            certificatePublic.setTrustStorePasswordSet(certificatePrivate.getTrustStorePassword() != null && !certificatePrivate.getTrustStorePassword().isEmpty());
            destination.setCertificate(certificatePublic);
        }
        return destination;
    }

    public CallbackUrlAuthenticationEntity fromNetworkObject(HttpAuthenticationPrivate source) {
        if (source == null) {
            return null;
        }
        final CallbackUrlAuthenticationEntity destination = new CallbackUrlAuthenticationEntity();
        final HttpAuthenticationPrivate.Certificate sc = source.getCertificate();
        if (sc != null) {
            final CallbackUrlAuthenticationEntity.Certificate certificate = new CallbackUrlAuthenticationEntity.Certificate();
            certificate.setEnabled(sc.isEnabled());
            certificate.setUseCustomKeyStore(sc.isUseCustomKeyStore());
            certificate.setKeyStoreLocation(sc.getKeyStoreLocation());
            certificate.setKeyStorePassword(sc.getKeyStorePassword());
            certificate.setKeyAlias(sc.getKeyAlias());
            certificate.setKeyPassword(sc.getKeyPassword());
            certificate.setUseCustomTrustStore(sc.isUseCustomTrustStore());
            certificate.setTrustStoreLocation(sc.getTrustStoreLocation());
            certificate.setTrustStorePassword(sc.getTrustStorePassword());
            destination.setCertificate(certificate);
        }
        final HttpAuthenticationPrivate.HttpBasic shb = source.getHttpBasic();
        if (shb != null) {
            final CallbackUrlAuthenticationEntity.HttpBasic httpBasic = new CallbackUrlAuthenticationEntity.HttpBasic();
            httpBasic.setEnabled(shb.isEnabled());
            httpBasic.setUsername(shb.getUsername());
            httpBasic.setPassword(shb.getPassword());
            destination.setHttpBasic(httpBasic);
        }
        return destination;
    }

}
