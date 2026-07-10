package com.mastercard.developer.oauth2.http.spring.webclient;

import static com.mastercard.developer.oauth2.http.spring.webclient.WebClientHttpAdapter.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;

/**
 * An OAuth2 filter for Spring WebClient.
 */
@SuppressWarnings("NullableProblems") // Spring API nullability varies across versions
public record OAuth2Filter(ReactiveOAuth2Handler handler, WebClientHttpAdapter adapter) implements ExchangeFilterFunction {
    /**
     * Creates a new OAuth2 filter for Spring WebClient.
     * @param config       A OAuth2 configuration.
     * @param baseBuilder  A WebClient builder to use as a starting point.
     */
    public OAuth2Filter(OAuth2Config config, WebClient.Builder baseBuilder) {
        this(new ReactiveOAuth2Handler(config), new WebClientHttpAdapter(baseBuilder.build()));
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return handler.execute(new ReactiveRequestContext(request, next), adapter).flatMap(materializedResponse ->
            Mono.just(
                ClientResponse.create(HttpStatusCode.valueOf(materializedResponse.statusCode()), ExchangeStrategies.withDefaults().messageReaders())
                    .headers(headers -> headers.addAll(materializedResponse.headers()))
                    .body(materializedResponse.body())
                    .build()
            )
        );
    }
}
