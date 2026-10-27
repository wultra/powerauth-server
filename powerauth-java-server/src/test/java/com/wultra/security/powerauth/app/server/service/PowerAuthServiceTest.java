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
package com.wultra.security.powerauth.app.server.service;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for {@link PowerAuthService}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
@Transactional
@ActiveProfiles("test")
@Sql
class PowerAuthServiceTest {

    private static final String ACTIVATION_ID = "e43a5dec-afea-4a10-a80b-b2183399f16b";

    @Autowired
    private ActivationServiceBehavior tested;

    @Autowired
    private ActivationRepository activationRepository;

    @Autowired
    private KeyProvider keyProvider;

    @Test
    void testGetActivationListForUser() throws Exception {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");
        request.setProtocols(Set.of(ActivationProtocol.POWERAUTH));

        final List<Activation> result = tested.getActivationList(request).getActivations();

        assertEquals(3, result.size());

        final List<String> expectedIdOrder = List.of("e43a5dec-afea-4a10-a80b-b2183399f16b", "47cf47b3-c72d-4859-a5f4-51da6d6ad6a3", "0d34cfc4-af98-4eb8-aba5-58f766bd2967");
        final List<String> actualIdOrder = result.stream().map(Activation::getActivationId).toList();
        assertEquals(expectedIdOrder, actualIdOrder);

        final Date timestampCreated1 = result.get(0).getTimestampCreated();
        final Date timestampCreated2 = result.get(1).getTimestampCreated();
        final Date timestampCreated3 = result.get(2).getTimestampCreated();
        assertEquals(1, timestampCreated1.compareTo(timestampCreated2));
        assertEquals(1, timestampCreated2.compareTo(timestampCreated3));

        final Activation committedActivation = result.get(0);
        assertEquals(ActivationStatus.ACTIVE, committedActivation.getActivationStatus());
        assertNotNull(committedActivation.getDevicePublicKeyBase64());
        assertTrue(result.stream().allMatch(a -> a.getDevicePublicKeys().isEmpty()));
    }

    @Test
    void testGetActivationListForUser_includeDevicePublicKeys() throws Exception {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");
        request.setProtocols(Set.of(ActivationProtocol.POWERAUTH));
        request.setIncludeDevicePublicKeys(true);

        final List<Activation> result = tested.getActivationList(request).getActivations();

        assertEquals(3, result.size());
        final Activation committedActivation = result.get(0);
        assertEquals(ActivationStatus.ACTIVE, committedActivation.getActivationStatus());
        assertEquals(Map.of(KeyType.ECDSA_P256.name(), committedActivation.getDevicePublicKeyBase64()), committedActivation.getDevicePublicKeys());
        assertNull(result.get(1).getDevicePublicKeyBase64());
        assertTrue(result.get(1).getDevicePublicKeys().isEmpty());
        assertNull(result.get(2).getDevicePublicKeyBase64());
        assertTrue(result.get(2).getDevicePublicKeys().isEmpty());
    }

    @Test
    void testGetActivationListForUser_includeDevicePublicKeysForEmptyResult() throws Exception {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("unknown-user");
        request.setIncludeDevicePublicKeys(true);

        assertTrue(tested.getActivationList(request).getActivations().isEmpty());
    }

    @Test
    void testLookupActivations() throws Exception {
        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.setUserIds(List.of("user1"));

        final List<Activation> result = tested.lookupActivations(request).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().allMatch(a -> a.getDevicePublicKeys().isEmpty()));
    }

    @Test
    void testLookupActivations_includeDevicePublicKeys() throws Exception {
        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.setUserIds(List.of("user1"));
        request.setIncludeDevicePublicKeys(true);

        final List<Activation> result = tested.lookupActivations(request).getActivations();

        assertEquals(3, result.size());
        final Activation committedActivation = result.stream()
                .filter(a -> a.getActivationStatus() == ActivationStatus.ACTIVE)
                .findFirst().orElseThrow();
        assertEquals(Map.of(KeyType.ECDSA_P256.name(), committedActivation.getDevicePublicKeyBase64()), committedActivation.getDevicePublicKeys());
        assertEquals(2, result.stream().filter(a -> a.getDevicePublicKeys().isEmpty()).count());
    }

    @Test
    void testLookupActivations_includeDevicePublicKeysForEmptyResult() throws Exception {
        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.setUserIds(List.of("unknown-user"));
        request.setIncludeDevicePublicKeys(true);

        assertTrue(tested.lookupActivations(request).getActivations().isEmpty());
    }

    @Test
    void testGetActivationListForUser_filterStatus() throws Exception {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");
        request.setProtocols(Set.of(ActivationProtocol.POWERAUTH));
        request.setActivationStatuses(Set.of(ActivationStatus.ACTIVE));

        final List<Activation> resultList = tested.getActivationList(request).getActivations();

        assertEquals(1, resultList.size());
        final Activation resultActivation = resultList.get(0);

        assertEquals("e43a5dec-afea-4a10-a80b-b2183399f16b", resultActivation.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, resultActivation.getActivationStatus());
    }

    @Test
    void testGetActivationListForUser_v4DevicePublicKeys() throws Exception {
        final Map<String, String> expectedKeys = storeV4DevicePublicKeys();

        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");
        request.setProtocols(Set.of(ActivationProtocol.POWERAUTH));
        request.setIncludeDevicePublicKeys(true);

        final Activation result = tested.getActivationList(request).getActivations().stream()
                .filter(a -> ACTIVATION_ID.equals(a.getActivationId()))
                .findFirst().orElseThrow();

        assertEquals(expectedKeys, result.getDevicePublicKeys());
    }

    @Test
    void testGetActivationListForUser_v4DevicePublicKeysNotIncludedByDefault() throws Exception {
        storeV4DevicePublicKeys();

        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");
        request.setProtocols(Set.of(ActivationProtocol.POWERAUTH));

        final List<Activation> result = tested.getActivationList(request).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().allMatch(a -> a.getDevicePublicKeys().isEmpty()));
    }

    @Test
    void testLookupActivations_v4DevicePublicKeys() throws Exception {
        final Map<String, String> expectedKeys = storeV4DevicePublicKeys();
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(ACTIVATION_ID).orElseThrow();
        activation.setVersion(4);
        activationRepository.save(activation);

        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.setUserIds(List.of("user1"));
        request.setIncludeDevicePublicKeys(true);

        final Activation result = tested.lookupActivations(request).getActivations().stream()
                .filter(a -> ACTIVATION_ID.equals(a.getActivationId()))
                .findFirst().orElseThrow();

        assertEquals(4L, result.getVersion());
        assertEquals("BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=", result.getDevicePublicKeyBase64());
        assertEquals(expectedKeys, result.getDevicePublicKeys());
    }

    @Test
    void testLookupActivations_v4DevicePublicKeysNotIncludedByDefault() throws Exception {
        storeV4DevicePublicKeys();

        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.setUserIds(List.of("user1"));

        final List<Activation> result = tested.lookupActivations(request).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().allMatch(a -> a.getDevicePublicKeys().isEmpty()));
    }

    @Test
    void testFindByUserIdAndExternalId_doesNotIncludeDevicePublicKeys() throws Exception {
        storeV4DevicePublicKeys();
        assignExternalId("credential-1");

        final List<Activation> result = tested.findByUserIdAndExternalId("user1", "credential-1");

        assertEquals(1, result.size());
        assertNotNull(result.get(0).getDevicePublicKeyBase64());
        assertTrue(result.get(0).getDevicePublicKeys().isEmpty());
    }

    @Test
    void testFindByExternalId_doesNotIncludeDevicePublicKeys() throws Exception {
        storeV4DevicePublicKeys();
        assignExternalId("credential-2");

        final List<Activation> result = tested.findByExternalId("221", "credential-2");

        assertEquals(1, result.size());
        assertNotNull(result.get(0).getDevicePublicKeyBase64());
        assertTrue(result.get(0).getDevicePublicKeys().isEmpty());
    }

    private void assignExternalId(final String externalId) {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(ACTIVATION_ID).orElseThrow();
        activation.setExternalId(externalId);
        activationRepository.save(activation);
    }

    private Map<String, String> storeV4DevicePublicKeys() throws Exception {
        final String ecdsaP384PublicKey = "BKJPKNYKmOx7O2uR1k1wR9NHUQFQVNghid1cNaHJ0HfGTYXpttIAsUkOlkY0DyIuAOcs+zpGRP87NlcdJALMfkKcXb22SAfy/E3D8HDCT038pYfL+HiwWpBP+5VYsmk28A==";
        final PublicKey ecdsaPublicKey = new KeyConvertor().convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode(ecdsaP384PublicKey));
        final PublicKey mlDsaPublicKey = new MlDsa().generateKeyPair().getPublic();
        final String mlDsaPublicKeyBase64 = Base64.getEncoder().encodeToString(new MlDsaKeyConvertor().convertPublicKeyToBytes(mlDsaPublicKey));

        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(ACTIVATION_ID).orElseThrow();
        activation.setVersion(4);
        keyProvider.storeDevicePublicKey(activation, KeyType.ECDSA_P384, ecdsaPublicKey);
        keyProvider.storeDevicePublicKey(activation, KeyType.MLDSA_87, mlDsaPublicKey);

        return Map.of(KeyType.ECDSA_P384.name(), ecdsaP384PublicKey, KeyType.MLDSA_87.name(), mlDsaPublicKeyBase64);
    }
}
