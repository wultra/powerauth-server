package io.getlime.security.powerauth.app.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OnlineSignatureServiceBehavior;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
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
    private final OnlineSignatureServiceBehavior onlineSignatureServiceBehavior;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();

    @Autowired
    public VerifySignatureConcurrencyTest(ApplicationServiceBehavior applicationServiceBehavior, ActivationServiceBehavior activationServiceBehavior, OnlineSignatureServiceBehavior onlineSignatureServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
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
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);

        // Generate expiration time
        Calendar expiration = Calendar.getInstance();
        expiration.add(Calendar.MINUTE, 5);

        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName("test_activation");
        requestL2.setDevicePublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));

        GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        GetApplicationDetailResponse detailResponse = applicationServiceBehavior.getApplicationDetail(detailRequest);

        PublicKey masterPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(detailResponse.getMasterPublicKey()));

        final String version = "3.2";
        final String applicationKey = createApplicationVersionResponse.getApplicationKey();
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version, applicationKey, null),
                new ClientEncryptorSecrets(masterPublicKey, createApplicationVersionResponse.getApplicationSecret())
        );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectMapper().writeValue(baos, requestL2);
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(baos.toByteArray());

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
        CreateActivationResponse createActivationResponse = activationServiceBehavior.createActivation(createActivationRequest);

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