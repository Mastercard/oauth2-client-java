package com.mastercard.developer.oauth2.test.fixtures;

import static com.mastercard.developer.oauth2.test.fixtures.LiveResourceRetry.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class LiveResourceRetryTest {

    @Test
    void retriesNotFoundUntilSuccess() throws Exception {
        var attempts = new AtomicInteger();

        String result = onNotFound("GET", () -> {
            if (attempts.incrementAndGet() == 1) {
                failIfNotFound(404);
            }
            return "found";
        });

        assertEquals("found", result);
        assertEquals(2, attempts.get());
    }

    @Test
    void doesNotRetryOtherErrors() {
        var attempts = new AtomicInteger();
        var error = new IOException("Other failure");

        assertSame(error, assertThrows(IOException.class, () -> onNotFound("GET", () -> {
            attempts.incrementAndGet();
            throw error;
        }, exception -> false)));
        assertEquals(1, attempts.get());
    }

    @Test
    void failsWithLastNotFoundAfterTenAttempts() {
        var attempts = new AtomicInteger();
        var error = new IOException("HTTP 404");

        assertSame(error, assertThrows(IOException.class, () -> onNotFound("DELETE", () -> {
            attempts.incrementAndGet();
            throw error;
        }, exception -> exception == error)));
        assertEquals(10, attempts.get());
    }
}
