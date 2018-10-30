package io.getlime.security.powerauth.app.server;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.v3.CreateApplicationRequest;
import io.getlime.security.powerauth.v3.CreateApplicationResponse;
import io.getlime.security.powerauth.v3.CreateApplicationVersionRequest;
import io.getlime.security.powerauth.v3.CreateApplicationVersionResponse;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Calendar;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
public class VerifySignatureConcurrencyTest {

    private PowerAuthService powerAuthService;

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    @Ignore("The test requires running MySQL database.")
    @Test
    public void testVerifySignatureConcurrent() throws Exception {

        // Generate test application
        String testId = "Test_"+System.currentTimeMillis();
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
        byte[] publicKeyBytes = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertPublicKeyToBytes(publicKey);

        // Generate random activation request values
        PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();
        byte[] activationNonce = serverActivation.generateActivationNonce();
        String activationNonceBase64 = BaseEncoding.base64().encode(activationNonce);
        String activationCode = serverActivation.generateActivationCode();
        String activationIdShort = activationCode.substring(0, 11);
        String activationOtp = activationCode.substring(12);

        // Derive and encrypt non-existent device public key
        SecretKey otpBasedSymmetricKey = new KeyGenerator().deriveSecretKeyFromPassword(activationOtp, activationIdShort.getBytes());
        byte[] encryptedDevicePublicKey = new AESEncryptionUtils().encrypt(publicKeyBytes, activationNonce, otpBasedSymmetricKey);
        String encryptedDevicePublicKeyBase64 = BaseEncoding.base64().encode(encryptedDevicePublicKey);

        // Compute application signature
        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        byte[] signature = clientActivation.computeApplicationSignature(
                activationIdShort,
                activationNonce,
                encryptedDevicePublicKey,
                BaseEncoding.base64().decode(createApplicationVersionResponse.getApplicationKey()),
                BaseEncoding.base64().decode(createApplicationVersionResponse.getApplicationSecret()));

        // Generate expiration time
        Calendar expiration = Calendar.getInstance();
        expiration.add(Calendar.MINUTE, 5);

        // Create activation

        // TODO - migrate test to version 3.0 once implemented
        /*
        CreateActivationRequest createActivationRequest = new CreateActivationRequest();
        createActivationRequest.setApplicationId(createApplicationResponse.getApplicationId());
        createActivationRequest.setUserId("test");
        createActivationRequest.setActivationName(testId);
        createActivationRequest.setTimestampActivationExpire(XMLGregorianCalendarConverter.convertFrom(expiration.getTime()));
        createActivationRequest.setEncryptedDevicePublicKey(encryptedDevicePublicKeyBase64);
        createActivationRequest.setActivationNonce(activationNonceBase64);
        createActivationRequest.setActivationOtp(activationOtp);
        createActivationRequest.setIdentity(activationIdShort);
        createActivationRequest.setApplicationKey(createApplicationVersionResponse.getApplicationKey());
        createActivationRequest.setApplicationSignature(BaseEncoding.base64().encode(signature));
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
                System.out.println("Signature verification response: "+response.isSignatureValid());
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
        */

    }
}