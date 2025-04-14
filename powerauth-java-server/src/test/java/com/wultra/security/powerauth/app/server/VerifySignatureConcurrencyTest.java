package com.wultra.security.powerauth.app.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.ActivationCreateServiceBehavior;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v3.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.v3.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.OnlineSignatureServiceBehavior;
import com.wultra.security.powerauth.app.server.service.model.request.v3.ActivationLayer2Request;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@Disabled("The test requires running database.")
public class VerifySignatureConcurrencyTest {

    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final ActivationServiceBehavior activationServiceBehavior;
    private final ActivationCreateServiceBehavior activationServiceBehaviorV3;
    private final OnlineSignatureServiceBehavior onlineSignatureServiceBehavior;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();

    @Autowired
    public VerifySignatureConcurrencyTest(ApplicationServiceBehavior applicationServiceBehavior, ActivationServiceBehavior activationServiceBehavior, ActivationCreateServiceBehavior activationServiceBehaviorV3, OnlineSignatureServiceBehavior onlineSignatureServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
        this.activationServiceBehaviorV3 = activationServiceBehaviorV3;
        this.onlineSignatureServiceBehavior = onlineSignatureServiceBehavior;
    }

    @Test
    public void testVerifySignatureConcurrent() throws Exception {

        // Generate test application
        String testId = UUID.randomUUID().toString();
        CreateApplicationRequest createApplicationRequest = new CreateApplicationRequest();
        createApplicationRequest.setApplicationId(testId);
        CreateApplicationResponse createApplicationResponse = applicationServiceBehavior.createApplication(createApplicationRequest);

        // Generate test application version
        CreateApplicationVersionRequest createApplicationVersionRequest = new CreateApplicationVersionRequest();
        createApplicationVersionRequest.setApplicationId(createApplicationResponse.getApplicationId());
        createApplicationVersionRequest.setApplicationVersionId("test");
        CreateApplicationVersionResponse createApplicationVersionResponse = applicationServiceBehavior.createApplicationVersion(createApplicationVersionRequest);

        // Generate public key for non-existent client device
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyPair keyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PublicKey publicKey = keyPair.getPublic();
        byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(EcCurve.P256, publicKey);

        // Generate expiration time
        Calendar expiration = Calendar.getInstance();
        expiration.add(Calendar.MINUTE, 5);

        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName("test_activation");
        requestL2.setDevicePublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));

        GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        GetApplicationDetailResponse detailResponse = applicationServiceBehavior.getApplicationDetail(detailRequest);

        PublicKey masterPublicKey = keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(detailResponse.getMasterPublicKey()));

        final String version = "3.2";
        final String applicationKey = createApplicationVersionResponse.getApplicationKey();
        final ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version, applicationKey, null, null),
                new ClientEciesSecrets(masterPublicKey, createApplicationVersionResponse.getApplicationSecret())
        );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectMapper().writeValue(baos, requestL2);
        final EciesEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(baos.toByteArray());

        // Create activation
        CreateActivationRequest createActivationRequest = new CreateActivationRequest();
        createActivationRequest.setUserId("test");
        createActivationRequest.setTimestampActivationExpire(expiration.getTime());
        createActivationRequest.setMaxFailureCount(5L);
        createActivationRequest.setApplicationKey(createApplicationVersionResponse.getApplicationKey());
        createActivationRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        createActivationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        createActivationRequest.setMac(encryptedRequest.getMac());
        createActivationRequest.setNonce(encryptedRequest.getNonce());
        createActivationRequest.setTimestamp(encryptedRequest.getTimestamp());
        createActivationRequest.setProtocolVersion(version);
        CreateActivationResponse createActivationResponse = activationServiceBehaviorV3.createActivation(createActivationRequest);

        // Commit activation
        CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(createActivationResponse.getActivationId());
        activationServiceBehavior.commitActivation(commitActivationRequest);

        // Finally here comes the test - create two threads and verify signatures in parallel
        Runnable verifySignatureRunnable = () -> {
            try {
                VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
                verifySignatureRequest.setActivationId(createActivationResponse.getActivationId());
                verifySignatureRequest.setApplicationKey(createApplicationVersionResponse.getApplicationKey());
                verifySignatureRequest.setSignatureType(SignatureType.KNOWLEDGE);
                verifySignatureRequest.setData("data");
                verifySignatureRequest.setSignature("bad signature");
                onlineSignatureServiceBehavior.verifySignature(verifySignatureRequest, null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        };

        // In case two threads are not enough, increase the THREAD_COUNT constant
        final int THREAD_COUNT = 2;

        List<Thread> threads = new ArrayList<>();
        for (int i=0; i<THREAD_COUNT; i++) {
            threads.add(new Thread(verifySignatureRunnable));
        }

        for (Thread t: threads) {
            t.start();
        }

        for (Thread t: threads) {
            t.join();
        }

    }
}