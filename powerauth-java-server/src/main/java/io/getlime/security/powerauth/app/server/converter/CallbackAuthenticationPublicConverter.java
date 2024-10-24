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
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import org.springframework.util.StringUtils;

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
    public HttpAuthenticationPublic toPublic(CallbackUrlAuthentication source) {
        final HttpAuthenticationPublic destination = new HttpAuthenticationPublic();
        if (source == null) {
            return destination;
        }

        final CallbackUrlAuthentication.HttpBasic httpBasicPrivate = source.getHttpBasic();
        if (httpBasicPrivate != null) {
            destination.setHttpBasic(convert(httpBasicPrivate));
        }

        final CallbackUrlAuthentication.Certificate certificatePrivate = source.getCertificate();
        if (certificatePrivate != null) {
            destination.setCertificate(convert(certificatePrivate));
        }

        final CallbackUrlAuthentication.OAuth2 oAuth2 = source.getOAuth2();
        if (oAuth2 != null) {
            destination.setOAuth2(convert(oAuth2));
        }

        return destination;
    }

    private static HttpAuthenticationPublic.OAuth2 convert(final CallbackUrlAuthentication.OAuth2 source) {
        final HttpAuthenticationPublic.OAuth2 target = new HttpAuthenticationPublic.OAuth2();
        target.setEnabled(source.isEnabled());
        target.setClientId(source.getClientId());
        target.setClientSecretSet(StringUtils.hasText(source.getClientSecret()));
        target.setScope(source.getScope());
        target.setTokenUri(source.getTokenUri());
        return target;
    }

    private static HttpAuthenticationPublic.Certificate convert(final CallbackUrlAuthentication.Certificate source) {
        final HttpAuthenticationPublic.Certificate target = new HttpAuthenticationPublic.Certificate();
        target.setEnabled(source.isEnabled());
        target.setUseCustomKeyStore(source.isUseCustomKeyStore());
        target.setKeyStoreLocation(source.getKeyStoreLocation());
        target.setKeyStorePasswordSet(StringUtils.hasText(source.getKeyStorePassword()));
        target.setKeyAlias(source.getKeyAlias());
        target.setKeyPasswordSet(StringUtils.hasText(source.getKeyPassword()));
        target.setUseCustomTrustStore(source.isUseCustomTrustStore());
        target.setTrustStoreLocation(source.getTrustStoreLocation());
        target.setTrustStorePasswordSet(StringUtils.hasText(source.getTrustStorePassword()));
        return target;
    }

    private static HttpAuthenticationPublic.HttpBasic convert(final CallbackUrlAuthentication.HttpBasic source) {
        final HttpAuthenticationPublic.HttpBasic target = new HttpAuthenticationPublic.HttpBasic();
        target.setEnabled(source.isEnabled());
        target.setUsername(source.getUsername());
        target.setPasswordSet(StringUtils.hasText(source.getPassword()));
        return target;
    }

    public CallbackUrlAuthentication fromNetworkObject(HttpAuthenticationPrivate source) {
        if (source == null) {
            return null;
        }

        final CallbackUrlAuthentication destination = new CallbackUrlAuthentication();
        final HttpAuthenticationPrivate.Certificate certificate = source.getCertificate();
        if (certificate != null) {
            destination.setCertificate(convert(certificate));
        }

        final HttpAuthenticationPrivate.HttpBasic httpBasic = source.getHttpBasic();
        if (httpBasic != null) {
            destination.setHttpBasic(convert(httpBasic));
        }

        final HttpAuthenticationPrivate.OAuth2 oAuth2 = source.getOAuth2();
        if (oAuth2 != null) {
            destination.setOAuth2(convert(oAuth2));
        }

        return destination;
    }

    private CallbackUrlAuthentication.OAuth2 convert(final HttpAuthenticationPrivate.OAuth2 source) {
        final CallbackUrlAuthentication.OAuth2 target = new CallbackUrlAuthentication.OAuth2();
        target.setEnabled(source.isEnabled());
        target.setClientId(source.getClientId());
        target.setScope(source.getScope());
        target.setTokenUri(source.getTokenUri());
        target.setClientSecret(source.getClientSecret());
        return target;
    }

    private static CallbackUrlAuthentication.Certificate convert(final HttpAuthenticationPrivate.Certificate source) {
        final CallbackUrlAuthentication.Certificate target = new CallbackUrlAuthentication.Certificate();
        target.setEnabled(source.isEnabled());
        target.setUseCustomKeyStore(source.isUseCustomKeyStore());
        target.setKeyStoreLocation(source.getKeyStoreLocation());
        target.setKeyStorePassword(source.getKeyStorePassword());
        target.setKeyAlias(source.getKeyAlias());
        target.setKeyPassword(source.getKeyPassword());
        target.setUseCustomTrustStore(source.isUseCustomTrustStore());
        target.setTrustStoreLocation(source.getTrustStoreLocation());
        target.setTrustStorePassword(source.getTrustStorePassword());
        return target;
    }

    private static CallbackUrlAuthentication.HttpBasic convert(final HttpAuthenticationPrivate.HttpBasic source) {
        final CallbackUrlAuthentication.HttpBasic target = new CallbackUrlAuthentication.HttpBasic();
        target.setEnabled(source.isEnabled());
        target.setUsername(source.getUsername());
        target.setPassword(source.getPassword());
        return target;
    }

}
