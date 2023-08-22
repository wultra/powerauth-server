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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ActivationServiceBehavior}.
 *
 * @author Jan Pesek, janpesek@outlook.com
 */
@SpringBootTest
@Transactional
public class ActivationServiceBehaviorTest {

    @Autowired
    private ActivationServiceBehavior tested;

    @Autowired
    private PowerAuthService powerAuthService;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final String version = "3.2";

    @Test
    public void testPrepareActivationWithValidPayload() throws Exception {

        // Create application
        GetApplicationDetailResponse detailResponse = this.createApplication();

        // Initiate activation of a user
        InitActivationResponse initActivationResponse = this.initActivation(detailResponse.getApplicationId());

        // Generate public key for a client device
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);

        // Create request payload
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setDevicePublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));
        EciesPayload correctEciesPayload = this.buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation
        assertDoesNotThrow(() -> tested.prepareActivation(
                initActivationResponse.getActivationCode(), detailResponse.getVersions().get(0).getApplicationKey(),
                false, correctEciesPayload, this.version, this.keyConvertor));
    }

    @Test
    public void testPrepareActivationWithInvalidPayload() throws Exception {

        // Create application
        GetApplicationDetailResponse detailResponse = this.createApplication();

        // Initiate activation of a user
        InitActivationResponse initActivationResponse = this.initActivation(detailResponse.getApplicationId());

        // Create request payload, omit device public key
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        EciesPayload invalidEciesPayload = this.buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation with missing devicePublicKey
        GenericServiceException exception = assertThrows(
                GenericServiceException.class,
                () -> tested.prepareActivation(initActivationResponse.getActivationCode(),
                        detailResponse.getVersions().get(0).getApplicationKey(),
                        false, invalidEciesPayload, this.version, this.keyConvertor));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    private EciesPayload buildPrepareActivationPayload(ActivationLayer2Request requestL2,
                                                       GetApplicationDetailResponse applicationDetail) throws Exception {

        // Set parameters
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final byte[] associatedData = EciesUtils.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, this.version, applicationKey, null);
        final Long timestamp = new Date().getTime();
        final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
        final EciesParameters eciesParameters = EciesParameters.builder().nonce(nonceBytes).associatedData(associatedData).timestamp(timestamp).build();

        final ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(
                Base64.getDecoder().decode(applicationDetail.getMasterPublicKey()));

        // Encrypt payload
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectMapper().writeValue(baos, requestL2);
        EciesEncryptor eciesEncryptor = new EciesFactory().getEciesEncryptorForApplication(masterPublicKey,
                applicationDetail.getVersions().get(0).getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                EciesSharedInfo1.ACTIVATION_LAYER_2, eciesParameters);
        return eciesEncryptor.encrypt(baos.toByteArray(), eciesParameters);
    }

    private InitActivationResponse initActivation(String applicationId) throws Exception {
        String userId = UUID.randomUUID().toString();
        return tested.initActivation(
                applicationId, userId,
                null, null, null,null,null,
                this.keyConvertor);
    }

    private GetApplicationDetailResponse createApplication() throws Exception {
        String testId = UUID.randomUUID().toString();
        CreateApplicationRequest createApplicationRequest = new CreateApplicationRequest();
        createApplicationRequest.setApplicationId(testId);
        CreateApplicationResponse createApplicationResponse = powerAuthService.createApplication(createApplicationRequest);

        GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        return powerAuthService.getApplicationDetail(detailRequest);
    }

}
