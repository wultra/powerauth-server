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
package io.getlime.security.powerauth.app.server.database.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationTemplateRepository}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@DataJpaTest
@Import(ObjectMapper.class)
class OperationTemplateRepositoryTest {

    @Autowired
    private OperationTemplateRepository repository;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    void testDuplicateOperationTemplateCreation() {
        final String templateName = "login";

        repository.save(createOperationTemplateEntity(templateName));
        entityManager.flush();

        Optional<OperationTemplateEntity> entity = repository.findTemplateByName(templateName);
        assertTrue(entity.isPresent());
        assertEquals(templateName, entity.get().getTemplateName());

        repository.save(createOperationTemplateEntity(templateName));
        assertThrows(ConstraintViolationException.class, () -> entityManager.flush());
    }

    private static OperationTemplateEntity createOperationTemplateEntity(String templateName) {
        final OperationTemplateEntity entity = new OperationTemplateEntity();
        entity.setTemplateName(templateName);
        entity.setOperationType(templateName);
        entity.setDataTemplate("A2");
        PowerAuthSignatureTypes[] signatureTypes = {PowerAuthSignatureTypes.POSSESSION};
        entity.setSignatureType(signatureTypes);
        entity.setMaxFailureCount(5L);
        entity.setExpiration(300L);
        return entity;
    }

}
