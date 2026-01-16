package com.mastercard.developer.oauth2.http;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Utility class to generate a User-Agent string used in HTTP requests.
 */
public final class UserAgent {

    private static final String PRODUCT = "Mastercard-OAuth2-Client";
    private static final String UNKNOWN_VERSION = "0.0.0-unknown";
    private static final String VERSION = readVersionFile();

    private UserAgent() {}

    /**
     * Builds a stable user-agent string:
     *   Product/Version (Runtime; OS [OS Version])
     * Example:
     *   Mastercard-OAuth2-Client/1.0.0 (Java/17.0.2; Linux 5.15)
     */
    public static String get() {
        String javaVer = System.getProperty("java.version", "unknown");
        String osName = System.getProperty("os.name", "unknown");
        String osVer = System.getProperty("os.version", "").trim();
        String runtime = "Java/" + javaVer;
        String osPart = osName + (osVer.isEmpty() ? "" : " " + osVer);
        return String.format("%s/%s (%s; %s)", PRODUCT, VERSION, runtime, osPart);
    }

    private static String readVersionFile() {
        try (InputStream in = UserAgent.class.getResourceAsStream("/VERSION")) {
            if (in != null) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
        } catch (IOException e) {
            // Should not happen
        }
        return UNKNOWN_VERSION;
    }
}
