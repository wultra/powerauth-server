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

package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.JwtSignatureFormat;
import com.wultra.security.powerauth.client.model.request.v4.SignJwtRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyJwtSignatureRequest;
import com.wultra.security.powerauth.client.model.response.v4.SignJwtResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyJwtSignatureResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Test for {@link JwtSignatureServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class JwtSignatureServiceBehaviorTest {

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private ActivationQueryService activationQueryService;

    @Mock
    private ActivationContextValidator activationValidator;

    @Mock
    private CryptographyServiceFactory cryptographyServiceFactory;

    @Mock
    private CryptographyService cryptographyService;

    @InjectMocks
    private JwtSignatureServiceBehavior tested;

    private ActivationRecordEntity activation;
    private final Base64URL dataToSign = Base64URL.encode("DataToSign");
    private final String activationId = "78f184f2-c434-474f-971e-9c2d255faf8c";

    @BeforeEach
    void setUp() {
        activation = new ActivationRecordEntity();
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setProtocol(ActivationProtocol.POWERAUTH);
        activation.setCryptoAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
    }

    @Test
    void signJwt_validEcdsa() throws Exception {
        String signatureEcdsaDer = "MGUCMHSj_atLUNwJrM0q8-PTtvNPpftHSGX3ErcyCwqfqZ0Ia627POEla-gaAcALqdLGjAIxAMa19AkR63k4HItcvqDcOuhgKv-E5PFcWXF1dkpgNq7jjvBMM3G1jYt7dG-DsVF71Q";
        String signatureEcdsaRaw = "dKP9q0tQ3AmszSrz49O280-l-0dIZfcStzILCp-pnQhrrbs84SVr6BoBwAup0saMxrX0CRHreTgci1y-oNw66GAq_4Tk8VxZcXV2SmA2ruOO8EwzcbWNi3t0b4OxUXvV";

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.ECDSA_P384), any(), eq(activation)))
                .thenReturn(Base64URL.from(signatureEcdsaDer).decode());

        SignJwtRequest request = new SignJwtRequest();
        request.setActivationId(activationId);
        request.setData(dataToSign.toString());
        request.setSignatureFormat(JwtSignatureFormat.JWS_COMPACT);
        request.setSignatureType(AsymmetricSignatureType.ECDSA);

        SignJwtResponse response = tested.signJwt(request);

        assertNotNull(response.getSignedData());
        assertEquals(JwtSignatureFormat.JWS_COMPACT, response.getSignatureFormat());
        SignedJWT jwt = SignedJWT.parse(response.getSignedData());
        assertEquals("ES384", jwt.getHeader().getAlgorithm().getName());
        assertEquals(signatureEcdsaRaw, jwt.getSignature().toString());
    }

    @Test
    void signJwt_invalidState() {
        activation.setActivationStatus(ActivationStatus.REMOVED);
        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_INCORRECT_STATE, "Activation is in removed state"));

        SignJwtRequest request = new SignJwtRequest();
        request.setActivationId(activationId);
        request.setData(dataToSign.toString());

        assertThrows(GenericServiceException.class, () -> tested.signJwt(request));
    }

    @Test
    void signJwt_activationNotFound() {
        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_NOT_FOUND, "Activation not found"));

        SignJwtRequest request = new SignJwtRequest();
        request.setActivationId(activationId);
        request.setData(dataToSign.toString());

        assertThrows(GenericServiceException.class, () -> tested.signJwt(request));
    }

    @Test
    void signJws_validHybrid() throws Exception {
        // given
        String signatureEcdsaDer = "MGUCMHSj_atLUNwJrM0q8-PTtvNPpftHSGX3ErcyCwqfqZ0Ia627POEla-gaAcALqdLGjAIxAMa19AkR63k4HItcvqDcOuhgKv-E5PFcWXF1dkpgNq7jjvBMM3G1jYt7dG-DsVF71Q";
        String signatureEcdsaRaw = "dKP9q0tQ3AmszSrz49O280-l-0dIZfcStzILCp-pnQhrrbs84SVr6BoBwAup0saMxrX0CRHreTgci1y-oNw66GAq_4Tk8VxZcXV2SmA2ruOO8EwzcbWNi3t0b4OxUXvV";
        String signatureMldsa = "UgQ_UPqHFY9foxoDM1AuJO9hEnSKoNtRtYNZWUntaPDbKct-rkyxTatncPcXWp7qUyfsmkyySPqulmaeqzlKFO58SQzILl0i8DGFX8_c4wgXR-quGn5N2DTA4of0pjUBWWMX24eG9L1Uz11qZlq08dqdAqfNZ-McM6MHQdqKa17AyepUbuGGWcZ-PI0EYCuHAi_EjutA9jMf3t3zqK8GCn5AAjBVMyDfWS6s6yHixIniEdejIT-vuCSq-zSDG8TZVn49qQvXnc_0OYuw-9yssu-ZnOOmWhfG4h_NqzzE0t3-pefCpXEdxE2NgoLzMVIcARsEmioSNQ9nofRJD7XKS-Nwmljfa-WlyPN1FMelPTzcthxE4cltdXsG5TSh8WqZqIU6zR9GEWEM5_b7WV8RRHYspJdq60WoOzPsxRHrGhHdCrbxCGE4yMWtAQrGjV0-vJQHJ2ywovVqR6rwdje2PaTzrw-lReaU6rFCa2_7XcFongj37ooN7Euhj9S3UvrEIm1_Ooi7Z2o-xxRC6Q7OvJaCatB6OsakdFq17vgK611kw8kmiJeC-QEHdoVo2MesRvWtakFXnJS0yc6LUW_cwzxTNxWejv8E9Nyq5YfADHAUZFXfgfLPzRtDVn6L5Um5JW2n7G6aYfxg0_jEpsNuHgorDWtBGvnO90Lg31JKjGuKDeb_aZsf5JjZOipJG_lgJTJQ7BIGZz2rkM1MQlSAgr1H2FZj6de_HZngNrsw26BbRf5F_yHrP6ztVHTimkhc_77AhFsOLRkvQ7Zz1aaj0M8I5r4m8RAZ3l4p-_-i_G75VV_CR1_huAPhPA8SYc4ZmNptH97SOeEbmh9G3XyFog5h8BtyinN9aqyFKOtRPMuZyoTPibTXZ9dPbmfnPTw9CuU5KoyjBKAUzd-ujP4VoOSF9DuZ5T309XYh2SDVU8BHhDuM3nIcJNSSAv2yVLYR_RWHC26Ry7wEjhNshYj_bnvR1mm8K7aaU2oIrr14dZ49Z4h--KW97mEju3Lu0W71rTkZGyn6O0D_NHlAPQuXfMhi8ZcJWOmgIUmhSwTIJMkrVlCCkDDPybqOJXsjtmmsZJF4whYUSu-hqb_EWMr-cLOTJVOhccLAyLpR2y7rvgkvhSbGKjmPkDzlSr5oTrCKfOTo4qbFKTntRsNNg_6_xO09y__4UoVNdpW3OzCMVVPrBEdqwB8NgQ-34ZhbwwwLW7dyF9kR_m4CjdV511iooILW2NDjTbzPNX-CYhc24Yh6QexDLvhEY_U0RW_4FNxa15E4aDvmICAHriqF5A6iYvIN2CvVwJ45XMyJ8aICoqHgu-SXSpddJKKAqPbWxo_WQ_8EffOImK5XicrmsOb4m44NYBqMsV3aJwapHjRNqBCTM04obLcBK5ffrU61keO5mjNuAM69C_JqpAjRuFep241m8YwS48vn-qKjLfcjU4fN8yHOCBrM_MSMGytGg4NZ9DhuBld5BAwU4acAjhbBNhcwLvpqufAKh459HdFNe9A3QalHMQvDvA6GUpj-9y9WPmkkXcAI_momwJu9En-GeXC_besoAUlIoEy-QII9HQ0qHy_wOJ7ljVDkFqPYET361BWt6elDJepJ7zhVtwpqc9JrR5Y9fcdQToItX4zZL74gnzX3hxmnhWf9EupBYBznNvaN0h5LeCYrKuvUfZe47HBGA8PgrkGYZSSJlF0kczDpm9syOElIqt2uab3tRFcWcujlWfssy0GqRLp4u65iR11x6cVg3wxUV_--VJldNWpCY8hMUD5a7HHq_dQUTivFfk7OKJDHvpV7LMm_fsqGS7xpVi83V9CF17VdAAbsrC0_IqN_wDX_4WtcdqpxjAmaqbFDY68m3x8y3pqFKVCNqkS2nqO_BkOV5Iv14AbJzbF7qCLSep_i_KXliimGMUG3LNtCgz8Ku3kIyfxbrE9tQybIhpYvFM1xdLLNvGgyRjnIpyn-Z-EyloWS84S52kpi90udRgmwxLpDTRbnrlBiiakEM2I_kHo5KoyvTNb-dEX0XLrFpq_kQ2-9DS0A9AprjlW5v_kYdchlWPZfbhozbh0jicp9wcX-XoNTAqBlE_RMiLwImQVx1ZtWZXB0XfCljtVvZfSoBRjKwcQ2w6p2MlMfOtpNsmv06uCjVCVqUimIvdtWqOgkLSSi6f7BFDTzC2Cex4AI0141atosYmardR5hWSLtLFyItdrYJGOR2V-1XNK01KcpD7Zh5JdOwj9QupwUfbl3ZcIC8NL9yldkuBRBYQB9WAIOXXK27AP2Uue-q-Pq_uK1Iq8WQS0EVOFKcDczJRcJ2XlL9AyJqi86nZP-7kVFZny0ZTxl4etlRqDxWtzRd-vItuMm8mUa0BApE1XvMYikk_nPk3i9ulzSx0xHO2JTMS_XKCxHbcdonh-sWOLmtElF225ZTRn2j-LiOu3eAHwftohcZLlJuVB_Np2ZMDTknZchCPOX8OVyOtGESLEZhjl0-1aoHtyQ8aQ-hUGXpRnqYoovebwIeWH4R9fHTuAqezlC-LOKfaNl0gR-rMZta-_fLrJLsrqlEbWIJKWLUgqHi8zVMTgWZbB_owDHpMb_yUTjZ8cqagFNiVG-08RTyrG6NrTPwWnLZupdoMxI4vGDwEWWVnDN8JGrvXzz2KmRf8z7KrtxSedYe1TNpkRUMjIJPDe-CnEW59FOW0VuOmXJ_joW_Dq5bPFBUkaqCuBgW6qBp1B3U2utMAnvRFPMEi_vr9z4pfo3lVrSD2bNlLWsQWbRibJkH7NKo5BW5AKqyPHx9NghrCOW3ADjnWol2_6lKfhFnpcPiF1pGS7JPL4Ghb5hB2eQuOXYJwgH_KkUXG6O862huGfxuL2prUbhs1fChTG1lgYqvtNUPxg16XbFZYD3LR0Z0jMZ1YzV07LCtMucCNFS83yQB-DgjEimpznhMCuAj8-Xp4b4ibecL8RwpseH4MFDum389b-4-TL__amzwsM_TMmtO_i1Uru0l4i4iqKKfuP-G231RELMI5RL_XiFBDaIvDhugdI0qFrCUmr216301_fl2tVYa3LmRh3onj_imUeuL0JRjUeBX7wsaJJo0I5hCpyht7nuoK0JrucdgAqBhBQYwHp_Eco7ZR9H9OjhEDAzVf2Qe3zohgdZzq-As-_SPHOA8xtJz-ZHcbMQjTDllFamQfb4KAElu70XDRWw4w6nwwBWVhg2jarb1ew15xq3Vf3A_FIZtl76tFYAqeTVL3PtxECdqxlu8cUz4QtHzK1VfpiSk2ZtztYK60e-xkyhIZIjAx6cKozVGrdPM7F_KIxicmZk_TdAA9HkI-6UDdAJI9G1nAddp9db8DRwfiV_c1dYI6bJZBf5tWIUQ5ZVZx9IQYdXQV1SLte3yTUQ_vPc7q-ibp3NyEy9ABZAKSW4tEs1EMjqUJXvjZUkoQm94QW2OefPrZCP0TSBHr0Tc60YEw8-KvOTbl4_7we1Kox-DXRVsCIP9IF4MPcc7E9BJVdsbbVdMIDboiiJ8VLiwMF_GJZk_fRd2FRlrQZ8m6UBa7ZOFAgFkzOew3mJJX7FhIsoGw3ueJTuvMv7qi00pWto05APCiD3btGekIadBULzQE84Sjacd7tejW_pEimkH3mOl4k9dTfxJFwwULHGQ-4mAHt1-R7HXclzLLXih8E_Uxy1UAcEpkEklBKlv8h4qUkN-Cocsf8AASYg4Aixd9IiPn9lUTrARGkAoq1iyZcPR18dD_poq_r03bn4pd-yM23sDxJrt-DVTpzE-cLGWrbz4pME3EG3_mtkHDApqlzJlWqZLNOgUE9iZsgo0dqvR_vWWdaJ6-6ZawZCyhP5OhSke4sFr_Lgc0x2jS2DXcA3ZCMyeYlPH3vwigZRBGrsUiiil6NrONvnwGKZgK8imdTUC3n43NzV8driC3CU_QUV3WYGbYyOYayOIVy53MmLJK5WM10FS4M_qplWaX-R6MYdVR3IVYDNi8bGn-izGgSYjcWynKuOwjs1kTo8wSHZi-dgoatVjoEonv0frOY9qWkRs9co_s-vjaryLt99hg9TV0tZI-Lt4UmUgySjTccJroX0Xtbw4nr3Md5Q0JS42Y2RAkDhAChwDpjr5esF9p--70F8ae7rY8C49p4RR6uxue_JYeOrkritTV3RqAlgZMHDttRtKb9lhvW4PvX5P0TcXFC2NhFum0mV91_I38Nq8vNS53B-yutgqQmKfmuBjzzsE3zpJm0Lq1hw2QrNVrjOxgJjxlWg5GQ5V6u5E3B5wzt-KcYSas-sP0Otd0d7jTXx1thOwuqCgB4vNMH80wV5W2fSUufrHLOq04EDRAIZwSePdkdRVsMhMlaZxQpyqdP7K6C5BBQWOjxhZHWKk73g-ClXbIWpub_O5wAAAAAAAAAAAAAAAAAAAAAAAwgNEB0m";

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.ECDSA_P384), any(), eq(activation)))
                .thenReturn(Base64URL.from(signatureEcdsaDer).decode());
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.MLDSA_65), any(), eq(activation)))
                .thenReturn(Base64URL.from(signatureMldsa).decode());

        SignJwtRequest request = new SignJwtRequest();
        request.setActivationId(activationId);
        request.setData(dataToSign.toString());
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        SignJwtResponse response = tested.signJwt(request);
        assertNotNull(response.getSignedData());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jwsJson = mapper.readTree(response.getSignedData());
        assertTrue(jwsJson.has("payload"));
        assertTrue(jwsJson.has("signatures"));
        JsonNode signatures = jwsJson.get("signatures");
        assertEquals(2, signatures.size());
        JsonNode es384Sig = signatures.get(0);
        assertEquals("eyJhbGciOiJFUzM4NCJ9", es384Sig.get("protected").asText());
        assertEquals(signatureEcdsaRaw, es384Sig.get("signature").asText());
        JsonNode mlDsaSig = signatures.get(1);
        assertEquals("eyJhbGciOiJNTC1EU0EtNjUifQ", mlDsaSig.get("protected").asText());
        assertEquals(signatureMldsa, mlDsaSig.get("signature").asText());
    }

    @Test
    void verifyJwsSignature_valid() throws Exception {
        String jwsJson = """
        {"payload":"UGF5bG9hZA","signatures":[
           {"protected":"eyJhbGciOiJFUzM4NCJ9","signature":"c2ln"}
        ]}
        """;

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(any(), any(), any(), eq(activation)))
                .thenReturn(true);

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(jwsJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        VerifyJwtSignatureResponse response = tested.verifyJwtSignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifyJwtSignature_invalidJwt() {
        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid JWT"));

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData("not-a-jwt");
        request.setSignatureFormat(JwtSignatureFormat.JWS_COMPACT);

        assertThrows(GenericServiceException.class, () -> tested.verifyJwtSignature(request));
    }

    @Test
    void verifyJwtSignature_activationNotFound() {
        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_NOT_FOUND, "Missing activation"));

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData("fake");
        request.setSignatureFormat(JwtSignatureFormat.JWS_COMPACT);

        assertThrows(GenericServiceException.class, () -> tested.verifyJwtSignature(request));
    }

    @Test
    void verifyJwsSignature_hybridDualSignatures_valid() throws Exception {
        String jwsJson = """
    {
      "payload": "UGF5bG9hZA",
      "signatures": [
        {
          "protected": "eyJhbGciOiJFUzM4NCJ9",
          "signature": "c2lnMQ"
        },
        {
          "protected": "eyJhbGciOiJNTC1EU0EtNjUifQ",
          "signature": "c2lnMg"
        }
      ]
    }
    """;

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(any(), any(), any(), eq(activation)))
                .thenReturn(true);

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(jwsJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        VerifyJwtSignatureResponse response = tested.verifyJwtSignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifyJwsSignature_hybridDualSignatures_oneInvalid() throws Exception {
        String jwsJson = """
    {
      "payload": "UGF5bG9hZA",
      "signatures": [
        {
          "protected": "eyJhbGciOiJFUzM4NCJ9",
          "signature": "c2lnMQ"
        },
        {
          "protected": "eyJhbGciOiJNTC1EU0EtNjUifQ",
          "signature": "c2lnMg"
        }
      ]
    }
    """;

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.ECDSA_P384), any(), any(), eq(activation)))
                .thenReturn(true);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.MLDSA_65), any(), any(), eq(activation)))
                .thenReturn(false);

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(jwsJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        VerifyJwtSignatureResponse response = tested.verifyJwtSignature(request);
        assertFalse(response.isSignatureValid());
    }

    @Test
    void verifyJwsSignature_hybridDualSignatures_bothInvalid() throws Exception {
        String jwsJson = """
    {
      "payload": "UGF5bG9hZA",
      "signatures": [
        {
          "protected": "eyJhbGciOiJFUzM4NCJ9",
          "signature": "c2lnMQ"
        },
        {
          "protected": "eyJhbGciOiJNTERTQS02NSJ9",
          "signature": "c2lnMg"
        }
      ]
    }
    """;

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(any(), any(), any(), eq(activation)))
                .thenReturn(false);

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(jwsJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        VerifyJwtSignatureResponse response = tested.verifyJwtSignature(request);
        assertFalse(response.isSignatureValid());
    }

    @Test
    void verifyJwsSignature_malformedJson() {
        String malformedJson = """
        {"payload":"UGF5bG9hZA","signatures":[{"protected":"eyJhbGciOiJFUzM4NCJ9","signature":c2ln]}
        """;

        when(activationQueryService.findActivationWithoutLock(activationId))
                .thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Malformed JWS JSON"));

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(malformedJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        assertThrows(GenericServiceException.class, () -> tested.verifyJwtSignature(request));
    }

    @Test
    void verifyJwsSignature_invalidBase64Payload() throws GenericServiceException {
        String jwsJson = """
        {
          "payload": "UGF5bG9h#ZA",
          "signatures": [
            {
              "protected": "eyJhbGciOiJFUzM4NCJ9",
              "signature": "c2ln"
            }
          ]
        }
        """;

        when(activationQueryService.findActivationWithoutLock(activationId))
                .thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(jwsJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        VerifyJwtSignatureResponse response = tested.verifyJwtSignature(request);
        assertFalse(response.isSignatureValid());
    }

    @Test
    void verifyJwsSignature_missingSignatures() {
        String jwsJson = """
        {
          "payload": "UGF5bG9hZA"
        }
        """;

        when(activationQueryService.findActivationWithoutLock(activationId))
                .thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Missing signatures"));

        VerifyJwtSignatureRequest request = new VerifyJwtSignatureRequest();
        request.setActivationId(activationId);
        request.setSignedData(jwsJson);
        request.setSignatureFormat(JwtSignatureFormat.JWS_JSON);

        assertThrows(GenericServiceException.class, () -> tested.verifyJwtSignature(request));
    }

}
