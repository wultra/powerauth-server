package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
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
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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

    @Test
    void testPrepareActivation() throws Exception {
        // Testing validation of encrypted data, sent in activation prepare endpoint.

        String testId = UUID.randomUUID().toString();
        CreateApplicationRequest createApplicationRequest = new CreateApplicationRequest();
        createApplicationRequest.setApplicationId(testId);
        CreateApplicationResponse createApplicationResponse = powerAuthService.createApplication(createApplicationRequest);

        CreateApplicationVersionRequest createApplicationVersionRequest = new CreateApplicationVersionRequest();
        createApplicationVersionRequest.setApplicationId(createApplicationResponse.getApplicationId());
        createApplicationVersionRequest.setApplicationVersionId("test");
        CreateApplicationVersionResponse createApplicationVersionResponse = powerAuthService.createApplicationVersion(createApplicationVersionRequest);

        GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        GetApplicationDetailResponse detailResponse = powerAuthService.getApplicationDetail(detailRequest);

        ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(detailResponse.getMasterPublicKey()));

        // Build Request; omit devicePublicKey for this test
        // other attributes have logic based on null value or are optional
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();

        final String version = "3.2";
        String activationCode = "AAAAA-BBBBB-CCCCC-DDDDD";
        boolean shouldGenerateRecoveryCodes = false;
        final String applicationKey = createApplicationVersionResponse.getApplicationKey();
        final byte[] associatedData = EciesUtils.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, version, applicationKey, null);
        final Long timestamp = new Date().getTime();
        final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
        final EciesParameters eciesParameters = EciesParameters.builder().nonce(nonceBytes).associatedData(associatedData).timestamp(timestamp).build();

        EciesEncryptor eciesEncryptor = new EciesFactory().getEciesEncryptorForApplication(masterPublicKey,
                createApplicationVersionResponse.getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                EciesSharedInfo1.ACTIVATION_LAYER_2, eciesParameters);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectMapper().writeValue(baos, requestL2);
        EciesPayload eciesPayload = eciesEncryptor.encrypt(baos.toByteArray(), eciesParameters);


        Executable executable = () -> tested.prepareActivation(activationCode, applicationKey,
                shouldGenerateRecoveryCodes, eciesPayload, version, this.keyConvertor);
        GenericServiceException exception = assertThrows(GenericServiceException.class, executable);
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

}
