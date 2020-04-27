package io.getlime.security.powerauth.app.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.converter.v3.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.v3.*;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
@Ignore("The test requires running MySQL database.")
public class VerifySignatureConcurrencyTest {

    private PowerAuthService powerAuthService;

    private final KeyConvertor keyConvertor = new KeyConvertor();

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    @Test
    public void testVerifySignatureConcurrent() throws Exception {

        // Generate test application
        String testId = UUID.randomUUID().toString();
        CreateApplicationRequest createApplicationRequest = new CreateApplicationRequest();
        createApplicationRequest.setApplicationName(testId);
        CreateApplicationResponse createApplicationResponse = powerAuthService.createApplication(createApplicationRequest);

        // Generate test application version
        CreateApplicationVersionRequest createApplicationVersionRequest = new CreateApplicationVersionRequest();
        createApplicationVersionRequest.setApplicationId(createApplicationResponse.getApplicationId());
        createApplicationVersionRequest.setApplicationVersionName("test");
        CreateApplicationVersionResponse createApplicationVersionResponse = powerAuthService.createApplicationVersion(createApplicationVersionRequest);

        // Generate public key for non-existent client device
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);

        // Compute application signature
        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();

        // Generate expiration time
        Calendar expiration = Calendar.getInstance();
        expiration.add(Calendar.MINUTE, 5);

        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName("test_activation");
        requestL2.setDevicePublicKey(BaseEncoding.base64().encode(publicKeyBytes));

        GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        GetApplicationDetailResponse detailResponse = powerAuthService.getApplicationDetail(detailRequest);

        ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(BaseEncoding.base64().decode(detailResponse.getMasterPublicKey()));

        EciesEncryptor eciesEncryptor = new EciesFactory().getEciesEncryptorForApplication(masterPublicKey, createApplicationVersionResponse.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectMapper().writeValue(baos, requestL2);
        EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest(baos.toByteArray(), true);

        // Create activation
        CreateActivationRequest createActivationRequest = new CreateActivationRequest();
        createActivationRequest.setUserId("test");
        createActivationRequest.setTimestampActivationExpire(XMLGregorianCalendarConverter.convertFrom(expiration.getTime()));
        createActivationRequest.setMaxFailureCount(5L);
        createActivationRequest.setApplicationKey(createApplicationVersionResponse.getApplicationKey());
        createActivationRequest.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData()));
        createActivationRequest.setMac(BaseEncoding.base64().encode(eciesCryptogram.getMac()));
        createActivationRequest.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        createActivationRequest.setNonce(BaseEncoding.base64().encode(eciesCryptogram.getNonce()));
        CreateActivationResponse createActivationResponse = powerAuthService.createActivation(createActivationRequest);

        // Commit activation
        CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(createActivationResponse.getActivationId());
        CommitActivationResponse commitActivationResponse = powerAuthService.commitActivation(commitActivationRequest);

        // Finally here comes the test - create two threads and verify signatures in parallel
        Runnable verifySignatureRunnable = () -> {
            try {
                VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
                verifySignatureRequest.setActivationId(createActivationResponse.getActivationId());
                verifySignatureRequest.setApplicationKey(createApplicationVersionResponse.getApplicationKey());
                verifySignatureRequest.setSignatureType(SignatureType.KNOWLEDGE);
                verifySignatureRequest.setData("data");
                verifySignatureRequest.setSignature("bad signature");
                VerifySignatureResponse response = powerAuthService.verifySignature(verifySignatureRequest);
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