package com.mastercard.developer.oauth2.test.fixtures;

import com.mastercard.developer.oauth2.internal.json.JsonProvider;
import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import com.mastercard.developer.oauth2.test.mocks.FakeAuthorizationServer;
import com.mastercard.developer.oauth2.test.mocks.FakeResourceServer;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.junit.jupiter.params.provider.Arguments;
import org.opentest4j.TestAbortedException;

public abstract class BaseClientTest extends BaseTest {

    @RegisterExtension
    static FakeAuthorizationServer authorizationServer = new FakeAuthorizationServer();

    @RegisterExtension
    static FakeResourceServer resourceServer = new FakeResourceServer();

    @Override
    @BeforeEach
    void setUp() {
        super.setUp();

        // Default scenario
        useNominalScenario();
    }

    @AfterEach
    void tearDown() {
        authorizationServer.reset();
        resourceServer.reset();
    }

    protected void useNominalScenario() {
        authorizationServer.useNominalScenario();
        resourceServer.useNominalScenario();
    }

    protected void useInvalidClientAssertionScenario() {
        authorizationServer.useInvalidClientAssertionScenario();
        resourceServer.useNominalScenario();
    }

    protected void useInsufficientScopeScenario() {
        authorizationServer.useNominalScenario();
        resourceServer.useInsufficientScopeScenario();
    }

    protected static Stream<Arguments> testConfigProvider() {
        return Stream.of(
            createConfigArgument("Mastercard API", BaseClientTest::getMastercardConfig),
            createConfigArgument("Fake authorization and resource servers", BaseClientTest::getFakeConfig)
        );
    }

    protected static Stream<Arguments> serverAndKeyProvider() {
        return Stream.of(
            createConfigArgument("Mastercard API + EC DPoP key", BaseClientTest::getMastercardConfigWithEcKey),
            createConfigArgument("Mastercard API + RSA DPoP key", BaseClientTest::getMastercardConfigWithRsaKey),
            createConfigArgument("Fake authorization and resource servers + EC DPoP key", BaseClientTest::getFakeConfigWithEcKey),
            createConfigArgument("Fake authorization and resource servers + RSA DPoP key", BaseClientTest::getFakeConfigWithRsaKey)
        );
    }

    protected static TestConfig getMastercardConfig() {
        return runOrWrap(TestConfig::getMastercardApiConfig);
    }

    private static TestConfig getMastercardConfigWithEcKey() {
        return runOrWrap(() -> TestConfig.getMastercardApiConfig(StaticKeys.EC_KEY_PAIR));
    }

    private static TestConfig getMastercardConfigWithRsaKey() {
        return runOrWrap(() -> TestConfig.getMastercardApiConfig(StaticKeys.RSA_KEY_PAIR));
    }

    protected static TestConfig getFakeConfig() {
        return runOrWrap(() -> TestConfig.getFakeApiConfig(authorizationServer, resourceServer));
    }

    private static TestConfig getFakeConfigWithEcKey() {
        return runOrWrap(() -> TestConfig.getFakeApiConfig(authorizationServer, resourceServer, StaticKeys.EC_KEY_PAIR));
    }

    private static TestConfig getFakeConfigWithRsaKey() {
        return runOrWrap(() -> TestConfig.getFakeApiConfig(authorizationServer, resourceServer, StaticKeys.RSA_KEY_PAIR));
    }

    private static Arguments createConfigArgument(String name, Supplier<TestConfig> configSupplier) {
        return Arguments.of(Named.of(name, configSupplier));
    }

    protected static String readResourceId(String resource) throws OAuth2ClientJsonException {
        Map<String, Object> jsonMap = JsonProvider.getInstance().parse(resource);
        return (String) jsonMap.get("id");
    }

    private static <T> T runOrWrap(ThrowingSupplier<T> action) {
        try {
            return action.get();
        } catch (TestAbortedException | IllegalStateException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException(e);
        }
    }
}
