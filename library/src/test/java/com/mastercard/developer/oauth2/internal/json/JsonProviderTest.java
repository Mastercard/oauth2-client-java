package com.mastercard.developer.oauth2.internal.json;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class JsonProviderTest {

    @Test
    void getInstance_ShouldReturnSingleInstance() {
        JsonProvider provider1 = JsonProvider.getInstance();
        assertNotNull(provider1);
        JsonProvider provider2 = JsonProvider.getInstance();
        assertNotNull(provider2);
        assertSame(provider1, provider2);
    }

    @Test
    void getInstance_ShouldSelectJackson_WhenJackson3OnClasspath() {
        assertInstanceOf(JacksonJsonProvider.class, JsonProvider.getInstance());
    }
}
