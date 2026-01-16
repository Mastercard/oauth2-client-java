package com.mastercard.developer.oauth2.internal.json;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import java.util.Map;
import java.util.Optional;

public class JacksonJsonProvider implements JsonProvider {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REFERENCE = new TypeReference<>() {};

    @Override
    public Map<String, Object> parse(String json) throws OAuth2ClientJsonException {
        try {
            return mapper.readValue(json, MAP_TYPE_REFERENCE);
        } catch (Exception e) {
            throw new OAuth2ClientJsonException("Failed to read JSON", e);
        }
    }

    @Override
    public Optional<Map<String, Object>> tryParse(String json) {
        try {
            return Optional.of(parse(json));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public String write(Map<String, Object> jsonMap) throws OAuth2ClientJsonException {
        try {
            return mapper.writeValueAsString(jsonMap);
        } catch (Exception e) {
            throw new OAuth2ClientJsonException("Failed to write JSON", e);
        }
    }
}
