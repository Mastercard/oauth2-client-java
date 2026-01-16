package com.mastercard.developer.oauth2.internal.json;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.Optional;

public class GsonJsonProvider implements JsonProvider {

    private static final Gson gson = new Gson();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();

    @Override
    public Map<String, Object> parse(String json) throws OAuth2ClientJsonException {
        try {
            return gson.fromJson(json, MAP_TYPE);
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
            return gson.toJson(jsonMap);
        } catch (Exception e) {
            throw new OAuth2ClientJsonException("Failed to write JSON", e);
        }
    }
}
