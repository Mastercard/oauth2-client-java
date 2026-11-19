package com.mastercard.developer.oauth2.test.fixtures;

import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class LiveResourceRetry {

    private static final Logger logger = LoggerFactory.getLogger(LiveResourceRetry.class);
    private static final int MAX_ATTEMPTS = 10;

    private LiveResourceRetry() {
        // Test utility
    }

    public static <T> T onNotFound(String method, Callable<T> request) throws Exception {
        return onNotFound(method, request, error -> error instanceof NotFoundException);
    }

    public static <T> T onNotFound(boolean retryOn404, String method, Callable<T> request) throws Exception {
        return retryOn404 ? onNotFound(method, request) : request.call();
    }

    public static <T> T onNotFound(boolean retryOn404, String method, Callable<T> request, Predicate<Exception> isNotFound) throws Exception {
        return retryOn404 ? onNotFound(method, request, isNotFound) : request.call();
    }

    public static <T> T onNotFound(String method, Callable<T> request, Predicate<Exception> isNotFound) throws Exception {
        for (int attempt = 1; ; attempt++) {
            try {
                return request.call();
            } catch (Exception error) {
                if (!isNotFound.test(error) || attempt == MAX_ATTEMPTS) {
                    throw error;
                }
                logger.info("{} returned 404; retrying (attempt {} of {})", method, attempt + 1, MAX_ATTEMPTS);
                try {
                    TimeUnit.SECONDS.sleep(1);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw interrupted;
                }
            }
        }
    }

    public static void failIfNotFound(int status) {
        if (status == 404) {
            throw new NotFoundException();
        }
    }

    private static final class NotFoundException extends RuntimeException {

        private NotFoundException() {
            super("Resource request returned HTTP 404");
        }
    }
}
