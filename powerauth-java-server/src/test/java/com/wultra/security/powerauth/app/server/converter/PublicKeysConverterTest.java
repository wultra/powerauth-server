/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.converter;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Tests for {@link PublicKeysConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class PublicKeysConverterTest {

    private static final String ECDSA_PUBLIC_KEY = "BKJPKNYKmOx7O2uR1k1wR9NHUQFQVNghid1cNaHJ0HfGTYXpttIAsUkOlkY0DyIuAOcs+zpGRP87NlcdJALMfkKcXb22SAfy/E3D8HDCT038pYfL+HiwWpBP+5VYsmk28A==";
    private static final String MLDSA_PUBLIC_KEY = "MIIHsjALBglghkgBZQMEAxIDggehAKTi66ULAsxGZHhdqBCqvqxfAoLlLJH5/vDPZKPWCnG0RRaShY8plwvYP8AAvlfmbTjayd2UQuqGJozBsB/zawPPiYNo3Y2JkjM8smHZvAL1Edfl/T5lDmctdg77UE84sQ4TjlU/zorUZn2qUSy8MPoRKlqacS4R/7U0M1R++emL2S0CyMCPNUkDlpRA7f2kk+it6qCajrVnhHWB7hPGMmi3ieksBSjh+YvS9ksIV9vBdbh8ysyHyNgjMhE/cl8yooFHMW0hoMijvH7WVFOoPUL+QytXIuzhy1WfGk14LrlHyPL2wr0K6KCT1ueM2zruD2CpFEcdUuNXN0LEzeOtTCpyI9knmp1vZ3vGh6EAaEumq3Ci8s//d1x9bQ31iTAjsxT4dXJvLljoaBdNH8uXXOgdHP3nCI8GmiVfGDd3QUfLMM/4tpudrd1CLgbKVJa+kZtSEkivSa5iSVjr9pOyCGRV+IfzTCRQAneQMg4Tjo8HdfZMZkthh/Cb1+h07PEhofcDn9VxCwzJam91Bn2FqYAvpla1+pFfxFX90gm2J9Heix83wh60SFCRp93pm1rB7+dHZfuKbABLODvy2cXCaDrI8LVfLkNKBEXkKQJN3Q7xsBmWWAzahnsNrnQ8kw0DqvgSUJFqYIgtcsN8yYCOECHO/pCOkNXcES7vvpSiLBt7VvcVsevHiIrAbMUVY/8RSdLurvpIJbFoG+R/gykjBfR9OfFj9cBYZZyo1TaelN+TdrARG1dWdROJmeJXw2sUgUW0hL2U7+fAQBeNZ23IholTCdN6YZK2y9MBdvscRYrtzcxKzXdveHrmYTr0lUxgNiBh25uPynIbJr0eeikNeck8D1GMASwtDYCbFkcsP+m/nyvlTaRnMZeEX7rHzTDs0E0I0mrN0zytxBTKwW4ilEFf/e6d7LfaHh5FBl1Z3Nw9XAnxcJ2nIbgQRrvtLHyWc2LIcKkrioS8SVBNU1vHooNODamhMpQFtmkMUzYvjdZweJy362loPkEILq/0qTvg+vc/GZwP+415LW19Vdczl86ZK/Sr8FaG6mSBBXA0hgbd54SEsa/JQoVXCL7fxS5wo5V7dqdCYL5nP1aAmzJZqI/fHogkRAeQPtZIKMNyy26+lQzuE2zzUE6jWlJ1eiyOxhqG9DMYKK1XuBXhbOnu7Lw2Rgx1XjsK/TOqrN3n71XjEHgpDgYFvc+aG+JsGaOGdNPpBR1bP1T2m/Q0zp3bhuj5FX4oD2VYInkQJvsvnZdRjZMX1/IfQ2/pCouRGVA2Tw/IcKAJbOVz0NqGrM9zpRP5VQOXJAVSGKQHVybfOCYjcIBM6DuG2vSvE1sc9pm7Yv3N5tYxcDwllob40xARVlOYOSCm9sGpvcKA+G65CgJ6m11AqV4HGCea14XibMMBCsl8+hm3OuQCbvyKET/l/8bRRIdo68D35USbORH2mhx3lgxPSkktRgt6eWc/pdi7HST9ZRxWhzmtUkgbRSpMG9AEUm+ri4OPGeX6pnx5Kdp4zgFrYt8AjqX11iNw60aVz4hy+7vHDaP/79nD3UlKvt0SZGFe7uLSSGz0r5Bvjv3buNecXhP1GHVXX8k1/1ml5izla+UAmhnht2LFCAaUcZozv8XrRk5Onjj10rM3Df3mE+/jKHpsRviAV/SjN0RL4KcJsDgMx41gVJ5XMv/TITtDAEqn49RvRAnKy9dzfqrZrqPuklpOVybqcdGntE0qpUTW7v1m+EDsidzoZYjWVyy84aybsjxpCVjZT/5yeDV2l0xNUEJZsX55UeliiQS5t/3mJ2UJ8hSH/T9jVG7LqMHU1huFfNXN2YP2FyKGo2mTYS9DTG3nWWWIcoUoUCaVDQELyTl4LkXwH1RGxftlarNOzKatnUMTRddaTt1qDOsDpAquuKFpu33BZa3n/oVeb9WgXhUg8BM5f5kokhlWbIkLLHR1SrqjLsEsJUsZ5kVwDQZxMP6mMDyDP3snd+28MydLhHJXsadjktqhdqDqWzt7EKSwJe2BPxLqStD5FmsxOPaeNqcwRwq5BWSY7DA/DvvycW91kkUeVEm+uktvFGbo5z4Edn+XE4wkumcezJVSu/YJ32vCxy8ka47liAU9pRo+ZlmkDom50g9px1zFjYxX2iBD0GhKCl3TJORGNJCsNd8NKHGvlK3MwPv4DnYIK+tGvnbrSE8IFtz9i9wt8koh5GaXL0fPKBthzi162Tpbi8dNHROnUaYnH5sczNe+ctH0FG863QsIcAg3w+0v4Dr9eTOwDESgQQ89KYqHYHcFHjCqLbwhgwGsNuGvhJNB0sFRYMNqjtUsxvnWtbIuAUb/VmDLSWfyIp6fC3hik5KXHzju9kbUXuYFMy6r2FT0i14mnLR94UQCFVg/nWOQ0LeC/89Ye8MgNLb73+kDYJmuWglUbtY5fxzKMkWK4jWKI/0kAJk5u07ouN1yiZHz3qbcDnuvuT55HktIaSTyiXo0DXC94XuYVbH+t5G5ZVP9xvgsEyCI0emImvh4ainXsGEqH2HUScbLrKjkHLQkAFsPiIJM1AQMxODz6C+iL4YBEp7F8QUBRWWrM9kniki3Dh4FUzXYzchu4cc4VgTmBxm1";

    private static final String SERVER_PUBLIC_KEYS_JSON = "{\"publicKeys\":{\"ECDSA_P384\":\"" + ECDSA_PUBLIC_KEY + "\",\"MLDSA_65\":\"" + MLDSA_PUBLIC_KEY + "\"}}";

    @Autowired
    private PublicKeysConverter serverPublicKeysConverter;

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();

    @Test
    void testFromDbValue() throws Exception {
        final PublicKeyRegistry keyRegistry = new PublicKeyRegistry();
        final PublicKey ecdsaPublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PUBLIC_KEY));
        keyRegistry.storePublicKey(KeyType.ECDSA_P384, ecdsaPublicKey);
        final PublicKey mldsaPublicKey = KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(Base64.getDecoder().decode(MLDSA_PUBLIC_KEY));
        keyRegistry.storePublicKey(KeyType.MLDSA_65, mldsaPublicKey);
        final byte[] keyRegistryBytes = serverPublicKeysConverter.serialize(keyRegistry);
        assertEquals(SERVER_PUBLIC_KEYS_JSON, new String(keyRegistryBytes, StandardCharsets.UTF_8));
        final String keyRegistryBase64 = Base64.getEncoder().encodeToString(keyRegistryBytes);
        final PublicKeyRegistry serverPublicKeysActual = serverPublicKeysConverter.fromDBValue(keyRegistryBase64);
        final Optional<PublicKey> ecdsaPublicKeyActual = serverPublicKeysActual.getPublicKey(KeyType.ECDSA_P384);
        assertFalse(ecdsaPublicKeyActual.isEmpty());
        final byte[] ecdsaPublicKeyActualBytes = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecdsaPublicKeyActual.get());
        final Optional<PublicKey> mlDsaPublicKeyActual = serverPublicKeysActual.getPublicKey(KeyType.MLDSA_65);
        assertFalse(mlDsaPublicKeyActual.isEmpty());
        final byte[] mlDsaPublicKeyActualBytes = mlDsaPublicKeyActual.get().getEncoded();
        assertEquals(ECDSA_PUBLIC_KEY, Base64.getEncoder().encodeToString(ecdsaPublicKeyActualBytes));
        assertEquals(MLDSA_PUBLIC_KEY, Base64.getEncoder().encodeToString(mlDsaPublicKeyActualBytes));
    }

    @Test
    void testConversionBothWays() throws Exception {
        final PublicKeyRegistry keysExpected = serverPublicKeysConverter.deserialize(SERVER_PUBLIC_KEYS_JSON.getBytes(StandardCharsets.UTF_8));
        final String serializedKeys = serverPublicKeysConverter.toDBValue(keysExpected);
        final PublicKeyRegistry keysActual = serverPublicKeysConverter.fromDBValue(serializedKeys);
        assertEquals(keysExpected, keysActual);
    }

}
