# AGENTS.md

## Purpose

This repository contains a Java OAuth 2.0 / FAPI 2.0 client library plus generated OpenAPI test clients used only by tests. Prefer repository-specific changes over generic refactors.

## Repository Layout

- `pom.xml`: root aggregator for `test-clients` and `library`.
- `library/`: the publishable artifact `com.mastercard.developer:oauth2-client-java`.
- `library/src/main/java/com/mastercard/developer/oauth2/`:
  - `config/`: `OAuth2Config`, `SecurityProfile`, and config validation.
  - `core/`: auth flow logic, token handling, DPoP, and scope resolution.
  - `http/`: HTTP-client integrations for OkHttp, Java `HttpClient`, Apache HttpClient, Feign, Spring RestClient, and Spring WebClient.
  - `internal/`: JOSE and JSON-provider internals. Treat as implementation detail unless the task is explicitly internal.
  - `keys/`: key generation and loading utilities.
- `library/src/test/java/com/mastercard/developer/oauth2/`:
  - unit tests next to the corresponding package areas.
  - `test/fixtures`, `test/helpers`, `test/mocks`: shared test scaffolding, fake servers, and environment-backed integration config.
- `library/src/test/resources/keys/`: test keys and fixtures.
- `test-clients/`: Maven module that generates OpenAPI clients into `target/generated-sources` during build. Do not add hand-edited source files there unless the build setup itself is changing.
- `.github/workflows/`: CI definitions. Use them as the source of truth for targeted compatibility test commands.
- `res/`: README assets only.

## Baseline Expectations

- Java baseline is 17. CI also runs on Java 21 and 25.
- Maven is the build tool.
- The library intentionally uses `provided` scope for HTTP client and JSON dependencies. Preserve that zero-dependency runtime model unless the task explicitly changes packaging strategy.
- Runtime JSON support is intentionally pluggable. Do not hard-wire one provider unless required.

## Editing Guidance

- Keep public API changes deliberate. Most consumer-facing entry points live under `config`, `core`, `http`, and `keys`.
- When changing one HTTP client integration, inspect the sibling adapters to preserve cross-client behavior.
- Avoid editing generated output under `target/`.
- Preserve the existing package structure and naming. This repo is organized by capability and transport, not by framework layer.
- Keep changes ASCII unless a file already requires otherwise.

## Tests And Verification

- Root smoke test:
  - `mvn -B test`
- Formatting check:
  - `cd library && mvn spotless:check`
- Apply formatting when needed:
  - `cd library && mvn spotless:apply`

`library` tests include both fake-server coverage and optional real Mastercard API coverage.

- Real-service tests read `.env` from the repository root via `dotenv-java`.
- Copy `.env.example` to `.env` and fill in `CLIENT_ID`, `KID`, `TOKEN_ENDPOINT`, `ISSUER`, `API_BASE_URL`, `READ_SCOPES`, `WRITE_SCOPES`, and `PRIVATE_KEY` to enable them.
- If those values are missing, the real-service tests self-disable via JUnit assumptions, so local `mvn test` remains safe.

For narrow changes, prefer the CI-style targeted commands that isolate one integration:

- OkHttp:
  - `mvn -B test "-Dtest=com.mastercard.developer.oauth2.http.okhttp3.OAuth2InterceptorTest" "-Dsurefire.failIfNoSpecifiedTests=false"`
- Java HTTP Client:
  - `mvn -B test "-Dtest=com.mastercard.developer.oauth2.http.java.OAuth2HttpClientTest" "-Dsurefire.failIfNoSpecifiedTests=false"`
- Apache HttpClient:
  - `mvn -B test "-Dtest=com.mastercard.developer.oauth2.http.apache.OAuth2HttpClientTest" "-Dsurefire.failIfNoSpecifiedTests=false"`
- Feign:
  - `mvn -B test "-Dtest=com.mastercard.developer.oauth2.http.feign.OAuth2ClientTest" "-Dsurefire.failIfNoSpecifiedTests=false"`
- Spring RestClient:
  - `mvn -B test "-Dtest=com.mastercard.developer.oauth2.http.spring.restclient.OAuth2ClientHttpRequestInterceptorTest" "-Dsurefire.failIfNoSpecifiedTests=false"`
- Spring WebClient:
  - `mvn -B test "-Dtest=com.mastercard.developer.oauth2.http.spring.webclient.OAuth2FilterTest" "-Dsurefire.failIfNoSpecifiedTests=false"`

If you change dependency compatibility, mirror the property overrides used in `.github/workflows/` rather than inventing new ad hoc commands.

## Build Details Worth Knowing

- `test-clients` runs OpenAPI Generator during the Maven build and provides generated clients consumed by `library` tests.
- `library` uses:
  - `maven-compiler-plugin` with `release` 17
  - `spotless-maven-plugin` with Prettier Java formatting
  - `jacoco-maven-plugin` during test runs
  - `flatten-maven-plugin`, source/javadoc packaging, and GPG signing for publishing
- A `VERSION` file is generated into `library` build output during `generate-resources`.

## Practical Agent Workflow

- Read `README.md`, the relevant module `pom.xml`, and the package under change before editing.
- Run the smallest meaningful test set first, then widen to `mvn -B test` if the change touches shared logic.
- When changing behavior in `core` or `config`, expect multiple HTTP integrations to be affected and test accordingly.
- When changing OpenAPI-related compatibility behavior, inspect both `test-clients/pom.xml` and the matching workflow file in `.github/workflows/`.
