/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.configuration;

import com.wultra.security.powerauth.app.server.converter.PrivateKeyRegistryDeserializer;
import com.wultra.security.powerauth.app.server.converter.PrivateKeySerializer;
import com.wultra.security.powerauth.app.server.converter.PublicKeyRegistryDeserializer;
import com.wultra.security.powerauth.app.server.converter.PublicKeySerializer;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Object mapper configuration for serialization and deserialization of keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
public class KeyMapperConfiguration {

    @Bean(name = "privateKeyObjectMapper")
    public ObjectMapper privateKeyObjectMapper() {
        final SimpleModule module = new SimpleModule();
        module.addSerializer(PrivateKey.class, new PrivateKeySerializer());
        module.addDeserializer(PrivateKeyRegistry.class, new PrivateKeyRegistryDeserializer());
        return JsonMapper.builder().addModule(module).build();
    }

    @Bean(name = "publicKeyObjectMapper")
    public ObjectMapper publickeyObjectMapper() {
        final SimpleModule module = new SimpleModule();
        module.addSerializer(PublicKey.class, new PublicKeySerializer());
        module.addDeserializer(PublicKeyRegistry.class, new PublicKeyRegistryDeserializer());
        return JsonMapper.builder().addModule(module).build();
    }

}
