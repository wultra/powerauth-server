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

@SpringBootTest
public class ActivationServiceBehaviorTest {

    @Autowired
    private ActivationServiceBehavior tested;

    @Autowired
    private PowerAuthService powerAuthService;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final String version = "3.2";

    @Test
    @Transactional
    void testPrepareActivationWithValidPayload() throws Exception {

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
    @Transactional
    void testPrepareActivationWithInvalidPayload() throws Exception {

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
