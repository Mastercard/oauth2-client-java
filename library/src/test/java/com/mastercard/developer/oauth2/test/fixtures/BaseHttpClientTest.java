package com.mastercard.developer.oauth2.test.fixtures;

import org.junit.jupiter.api.Test;

public abstract class BaseHttpClientTest extends BaseClientTest {

    @Test
    protected void client_ShouldSucceed_WhenFakeServers() throws Exception {
        clientShouldSucceed(getFakeConfig(), false);
    }

    @Test
    protected void client_ShouldSucceed_WhenMastercardApi() throws Exception {
        clientShouldSucceed(getMastercardConfig(), true);
    }

    protected abstract void clientShouldSucceed(TestConfig testConfig, boolean retryOn404) throws Exception;
}
