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
package com.wultra.security.powerauth.app.server.database.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationTemplateRepository}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@DataJpaTest
@Import(ObjectMapper.class)
@ActiveProfiles("test")
@Sql
class OperationTemplateRepositoryTest {

    @Autowired
    private OperationTemplateRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Tests that {@code template_name} is enforced to be unique.
     */
    @Test
    void testDuplicateOperationTemplateCreation() {
        final String templateName = "login";

        final Optional<OperationTemplateEntity> entity = repository.findTemplateByName(templateName);
        assertTrue(entity.isPresent());
        assertEquals(templateName, entity.get().getTemplateName());

        final OperationTemplateEntity newEntity = createOperationTemplateEntity(templateName);
        assertThrows(DuplicateKeyException.class, () -> repository.save(newEntity));

        newEntity.setTemplateName("login_v2");
        final OperationTemplateEntity newlySaved = repository.save(newEntity);
        repository.deleteById(newlySaved.getId());
    }

    /**
     * Tests that fetching {@link OperationTemplateEntity} using the {@link OperationTemplateRepository} silently
     * handles legacy or unsupported values stored in the {@code signature_type} column of {@code pa_operation_template} table.
     */
    @Test
    void testHandlingUnsupportedSignatureTypes() {
        // Assert unsupported signature types are set
        final String rawSignatureTypes = jdbcTemplate.queryForObject("SELECT signature_type FROM pa_operation_template WHERE id = 1", String.class);
        assertEquals("possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry",  rawSignatureTypes);

        // Test the handling
        final Optional<OperationTemplateEntity> template = repository.findById(1L);
        assertTrue(template.isPresent());

        // Unsupported signature types are ignored
        assertThat(template.get().getSignatureType())
                .hasSize(3)
                .containsExactlyInAnyOrder(PowerAuthCodeType.POSSESSION, PowerAuthCodeType.POSSESSION_KNOWLEDGE, PowerAuthCodeType.POSSESSION_BIOMETRY);
    }

    /**
     * Tests that fetching {@link OperationTemplateEntity} using the {@link OperationTemplateRepository} silently
     * handles legacy or unsupported values stored in the {@code signature_type} column of {@code pa_operation_template} table.
     * If there are unsupported values only, {@link OperationTemplateEntity#getSignatureType()} is empty.
     */
    @Test
    void testHandlingTemplateWithUnsupportedSignatureTypesOnly() {
        // Assert unsupported signature types are set
        final String rawSignatureTypes = jdbcTemplate.queryForObject("SELECT signature_type FROM pa_operation_template WHERE id = 2", String.class);
        assertEquals("knowledge,biometry,possession_knowledge_biometry",  rawSignatureTypes);

        // Test the handling
        final Optional<OperationTemplateEntity> template = repository.findById(2L);
        assertTrue(template.isPresent());

        // Unsupported signature types are ignored
        assertThat(template.get().getSignatureType())
                .isNotNull()
                .isEmpty();
    }

    private static OperationTemplateEntity createOperationTemplateEntity(String templateName) {
        final OperationTemplateEntity entity = new OperationTemplateEntity();
        entity.setTemplateName(templateName);
        entity.setOperationType(templateName);
        entity.setDataTemplate("A2");
        PowerAuthCodeType[] authCodeTypes = {PowerAuthCodeType.POSSESSION};
        entity.setSignatureType(authCodeTypes);
        entity.setMaxFailureCount(5L);
        entity.setExpiration(300L);
        return entity;
    }

}
