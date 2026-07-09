package com.mastercard.developer.oauth2.internal.json;

import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import java.util.Map;
import java.util.Optional;

/**
 * Provides JSON serialization and deserialization.
 */
public interface JsonProvider {
    /**
     * Parses JSON text into a {@link Map} tree.
     * Throws {@link OAuth2ClientJsonException} if the operation fails.
     */
    Map<String, Object> parse(String json) throws OAuth2ClientJsonException;

    /**
     * Parses JSON text into a {@link Map} tree.
     * Returns an empty {@link Optional} if parsing fails.
     */
    Optional<Map<String, Object>> tryParse(String json);

    /**
     * Writes a {@link Map} tree to a JSON text.
     */
    String write(Map<String, Object> jsonMap) throws OAuth2ClientJsonException;

    /**
     * Returns a singleton instance of a {@link JsonProvider} based on available libraries.
     * Prefers Jackson, then Gson, then org.json.
     * Throws {@link OAuth2ClientJsonException} if none are available.
     */
    static JsonProvider getInstance() {
        return Holder.INSTANCE;
    }

    class Holder {

        private Holder() {}

        static final JsonProvider INSTANCE = createInstance();

        private static JsonProvider createInstance() {
            try {
                Class.forName("tools.jackson.databind.ObjectMapper"); // Jackson 3.x
                return new JacksonJsonProvider();
            } catch (ClassNotFoundException e) {
                // Jackson not available, try next
            }
            try {
                Class.forName("com.google.gson.Gson");
                return new GsonJsonProvider();
            } catch (ClassNotFoundException e) {
                // Gson not available, try next
            }
            try {
                Class.forName("org.json.JSONObject");
                return new JsonOrgJsonProvider();
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("At least one JSON library (Jackson, Gson, or org.json) must be available on the classpath for JSON processing");
            }
        }
    }
}
