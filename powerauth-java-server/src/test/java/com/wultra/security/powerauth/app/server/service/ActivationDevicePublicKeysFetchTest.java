/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.DevicePublicKeyEntity;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceContext;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of the database access pattern used when device public keys are (not) requested on activation lists.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest(properties = "spring.jpa.properties.hibernate.generate_statistics=true")
@Transactional
@ActiveProfiles("test")
@Sql("PowerAuthServiceTest.sql")
class ActivationDevicePublicKeysFetchTest {

    private static final List<String> ACTIVATION_IDS = List.of(
            "e43a5dec-afea-4a10-a80b-b2183399f16b",
            "47cf47b3-c72d-4859-a5f4-51da6d6ad6a3",
            "0d34cfc4-af98-4eb8-aba5-58f766bd2967");

    @Autowired
    private ActivationServiceBehavior tested;

    @Autowired
    private ActivationRepository activationRepository;

    @Autowired
    private KeyProvider keyProvider;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @PersistenceContext
    private EntityManager entityManager;

    private Statistics statistics;

    @BeforeEach
    void storeKeysForAllActivations() throws Exception {
        final String ecdsaP384PublicKey = "BKJPKNYKmOx7O2uR1k1wR9NHUQFQVNghid1cNaHJ0HfGTYXpttIAsUkOlkY0DyIuAOcs+zpGRP87NlcdJALMfkKcXb22SAfy/E3D8HDCT038pYfL+HiwWpBP+5VYsmk28A==";
        final PublicKey publicKey = new KeyConvertor().convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode(ecdsaP384PublicKey));
        for (final String activationId : ACTIVATION_IDS) {
            final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).orElseThrow();
            keyProvider.storeDevicePublicKey(activation, KeyType.ECDSA_P384, publicKey);
        }
        entityManager.flush();
        statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
    }

    @Test
    void activationListLoadsNoKeyRowsByDefault() throws Exception {
        resetPersistenceContext();

        final List<Activation> result = tested.getActivationList(listRequest(false)).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().allMatch(a -> a.getDevicePublicKeys().isEmpty()));
        assertEquals(0, keyRowsLoaded());
    }

    @Test
    void activationListLoadsKeyRowsInSingleStatementWhenRequested() throws Exception {
        tested.getActivationList(listRequest(false));
        resetPersistenceContext();
        tested.getActivationList(listRequest(false));
        final long baselineStatements = statistics.getPrepareStatementCount();

        resetPersistenceContext();
        final List<Activation> result = tested.getActivationList(listRequest(true)).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().noneMatch(a -> a.getDevicePublicKeys().isEmpty()));
        assertEquals(3, keyRowsLoaded());
        assertEquals(baselineStatements + 1, statistics.getPrepareStatementCount());
    }

    @Test
    void lookupLoadsNoKeyRowsByDefault() throws Exception {
        resetPersistenceContext();

        final List<Activation> result = tested.lookupActivations(lookupRequest(false)).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().allMatch(a -> a.getDevicePublicKeys().isEmpty()));
        assertEquals(0, keyRowsLoaded());
    }

    @Test
    void lookupLoadsKeyRowsInSingleStatementWhenRequested() throws Exception {
        tested.lookupActivations(lookupRequest(false));
        resetPersistenceContext();
        tested.lookupActivations(lookupRequest(false));
        final long baselineStatements = statistics.getPrepareStatementCount();

        resetPersistenceContext();
        final List<Activation> result = tested.lookupActivations(lookupRequest(true)).getActivations();

        assertEquals(3, result.size());
        assertTrue(result.stream().noneMatch(a -> a.getDevicePublicKeys().isEmpty()));
        assertEquals(3, keyRowsLoaded());
        assertEquals(baselineStatements + 1, statistics.getPrepareStatementCount());
    }

    private void resetPersistenceContext() {
        entityManager.flush();
        entityManager.clear();
        statistics.clear();
    }

    private long keyRowsLoaded() {
        return statistics.getEntityStatistics(DevicePublicKeyEntity.class.getName()).getLoadCount();
    }

    private static GetActivationListForUserRequest listRequest(final boolean includeDevicePublicKeys) {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");
        request.setProtocols(Set.of(ActivationProtocol.POWERAUTH));
        request.setIncludeDevicePublicKeys(includeDevicePublicKeys);
        return request;
    }

    private static LookupActivationsRequest lookupRequest(final boolean includeDevicePublicKeys) {
        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.setUserIds(List.of("user1"));
        request.setIncludeDevicePublicKeys(includeDevicePublicKeys);
        return request;
    }

}
