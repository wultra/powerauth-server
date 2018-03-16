package io.getlime.security.powerauth.app.server.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.KeyValueMap;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Converter for {@link KeyValueMap} to {@link String}.
 *
 * @author Roman Strobl, roman.strobl@lime-company.eu
 */
public class KeyValueMapConverter {

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Convert {@link KeyValueMap} to {@link String}.
     * @param keyValueMap KeyValueMap.
     * @return String value of KeyValueMap in JSON format.
     */
    public String toString(KeyValueMap keyValueMap) {
        if (keyValueMap == null) {
            return null;
        }
        try {
            return mapper.writeValueAsString(keyValueMap);
        } catch (JsonProcessingException ex) {
            Logger.getLogger(KeyValueMapConverter.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return null;
        }
    }

    /**
     * Convert {@link String} to {@link KeyValueMap}.
     * @param s String value of KeyValueMap in JSON format.
     * @return Constructed KeyValueMap.
     */
    public KeyValueMap fromString(String s) {
        if (s == null) {
            return new KeyValueMap();
        }
        try {
            return mapper.readValue(s, KeyValueMap.class);
        } catch (IOException ex) {
            Logger.getLogger(KeyValueMapConverter.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return new KeyValueMap();
        }
    }
}
