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

import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.SignatureEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.service.model.signature.OnlineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link SignatureSharedServiceBehavior}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
@Sql
@Transactional
class SignatureSharedServiceBehaviorTest {

    @Autowired
    private SignatureSharedServiceBehavior tested;

    @Autowired
    private EntityManager entityManager;

    @Test
    void testHandleValidSignature() {
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");
        final SignatureResponse signatureResponse = new SignatureResponse(true, 1L, new byte[]{'x'}, 3, SignatureType.POSSESSION_KNOWLEDGE);

        assertEquals(0, activation.getCounter());
        assertEquals("D5XibWWPCv+nOOfcdfnUGQ==", activation.getCtrDataBase64());

        tested.handleValidSignature(activation, signatureResponse, createOnlineSignatureRequest(), new Date());

        assertEquals(1, activation.getCounter());
        assertEquals("eA==", activation.getCtrDataBase64());

        final SignatureEntity signatureEntity = getSignatureEntityBy(activation);

        assertEquals(0, signatureEntity.getActivationCounter());
        assertEquals("D5XibWWPCv+nOOfcdfnUGQ==", signatureEntity.getActivationCtrDataBase64());
    }

    @Test
    void testHandleInactiveActivationWithMismatchSignature() {
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");

        assertEquals(ActivationStatus.ACTIVE, activation.getActivationStatus());

        tested.handleInactiveActivationWithMismatchSignature(activation, createOnlineSignatureRequest(), new Date());

        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());

        final SignatureEntity signatureEntity = getSignatureEntityBy(activation);
        assertEquals(ActivationStatus.ACTIVE, signatureEntity.getActivationStatus(), "Activation status has changed but audit should contain previous status");
    }

    @Test
    void testHandleInvalidApplicationVersion() {
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");

        assertEquals(ActivationStatus.ACTIVE, activation.getActivationStatus());

        tested.handleInvalidApplicationVersion(activation, createOnlineSignatureRequest(), new Date());

        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());

        final SignatureEntity signatureEntity = getSignatureEntityBy(activation);
        assertEquals(ActivationStatus.ACTIVE, signatureEntity.getActivationStatus(), "Activation status has changed but audit should contain previous status");
    }

    @Test
    void testHandleInvalidSignature() {
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");
        final SignatureResponse signatureResponse = new SignatureResponse(true, 1L, new byte[]{'x'}, 3, SignatureType.POSSESSION_KNOWLEDGE);

        assertEquals(ActivationStatus.ACTIVE, activation.getActivationStatus());

        tested.handleInvalidSignature(activation, signatureResponse, createOnlineSignatureRequest(), new Date());

        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());

        final SignatureEntity signatureEntity = getSignatureEntityBy(activation);
        assertEquals(ActivationStatus.ACTIVE, signatureEntity.getActivationStatus(), "Activation status has changed but audit should contain previous status");
    }

    private static OnlineSignatureRequest createOnlineSignatureRequest() {
        final byte[] data = Base64.getDecoder().decode("UE9TVCZMM0JoTDNOcFoyNWhkSFZ5WlM5MllXeHBaR0YwWlE9PSYyaVR6Ry9CMzVRSmY3SHhaZmNseUZnPT0mUVd4c0lIbHZkWElnWW1GelpTQmhjbVVnWW1Wc2IyNW5JSFJ2SUhWeklRPT0mbzk3MGdVQkx2d0NUZGJJT1BrWjBsdz09");
        final List<KeyValue> additionalInfo = new ArrayList<>();
        additionalInfo.add(new KeyValue());
        final SignatureData signatureData = new SignatureData(data, "39319618-09892741", SignatureConfiguration.decimal(), "3.0", additionalInfo, 3);
        return new OnlineSignatureRequest(signatureData, SignatureType.POSSESSION_KNOWLEDGE);
    }

    private SignatureEntity getSignatureEntityBy(ActivationRecordEntity activation) {
        return entityManager.createQuery("select s from SignatureEntity s where s.activation =: activation", SignatureEntity.class)
                .setParameter("activation", activation)
                .getResultList().stream()
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("No SignatureEntity found"));
    }
}
