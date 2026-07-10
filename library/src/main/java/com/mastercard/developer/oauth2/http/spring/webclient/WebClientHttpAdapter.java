package com.mastercard.developer.oauth2.http.spring.webclient;

import static com.mastercard.developer.oauth2.http.spring.webclient.WebClientHttpAdapter.MaterializedResponse;
import static com.mastercard.developer.oauth2.http.spring.webclient.WebClientHttpAdapter.ReactiveRequestContext;

import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import java.net.URL;
import java.util.Optional;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Internal adapter for Spring WebClient.
 */
record WebClientHttpAdapter(WebClient delegate) implements ReactiveOAuth2Handler.ReactiveHttpAdapter<ReactiveRequestContext, MaterializedResponse> {
    record ReactiveRequestContext(ClientRequest request, ExchangeFunction next) {}

    @Override
    public HttpAdapter<ReactiveRequestContext, MaterializedResponse> toBlockingAdapter() {
        return new BlockingAdapter(this);
    }

    Mono<MaterializedResponse> sendAccessTokenRequestReactive(URL tokenUrl, String formBody, HttpHeaders headers) {
        var requestSpec = delegate.post().uri(tokenUrl.toString());
        headers.forEach(header -> requestSpec.header(header.name(), header.value()));
        return requestSpec.bodyValue(formBody).exchangeToMono(response ->
            response
                .bodyToMono(String.class)
                .defaultIfEmpty("")
                .map(body -> new MaterializedResponse(response.statusCode().value(), response.headers().asHttpHeaders(), body))
        );
    }

    Mono<MaterializedResponse> sendResourceRequestReactive(ReactiveRequestContext request, HttpHeaders headers) {
        var originalRequest = request.request();
        // Add or replace HTTP headers in the original request
        var updatedRequest = ClientRequest.from(originalRequest)
            .headers(httpHeaders -> headers.forEach(header -> httpHeaders.set(header.name(), header.value())))
            .build();
        return request
            .next()
            .exchange(updatedRequest)
            .flatMap(response ->
                response
                    .bodyToMono(String.class)
                    .defaultIfEmpty("")
                    .map(body -> new MaterializedResponse(response.statusCode().value(), response.headers().asHttpHeaders(), body))
            );
    }

    record MaterializedResponse(int statusCode, org.springframework.http.HttpHeaders headers, String body) {}

    /**
     * Blocking adapter that wraps the reactive adapter for use with OAuth2Handler.
     */
    private record BlockingAdapter(WebClientHttpAdapter reactiveAdapter) implements HttpAdapter<ReactiveRequestContext, MaterializedResponse> {
        @Override
        public String getMethod(ReactiveRequestContext context) {
            return context.request().method().name();
        }

        @Override
        public URL getUrl(ReactiveRequestContext context) throws Exception {
            return context.request().url().toURL();
        }

        @Override
        public MaterializedResponse sendAccessTokenRequest(ReactiveRequestContext resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) {
            return reactiveAdapter.sendAccessTokenRequestReactive(tokenUrl, formBody, headers).block();
        }

        @Override
        public MaterializedResponse sendResourceRequest(ReactiveRequestContext request, HttpHeaders headers) {
            return reactiveAdapter.sendResourceRequestReactive(request, headers).block();
        }

        @Override
        public int getStatusCode(MaterializedResponse response) {
            return response.statusCode;
        }

        @Override
        public Optional<String> getHeader(MaterializedResponse response, String name) {
            return Optional.ofNullable(response.headers.getFirst(name));
        }

        @Override
        public Optional<String> readBody(MaterializedResponse response) {
            return Optional.ofNullable(response.body);
        }

        @Override
        public void close(MaterializedResponse response) {
            // No-op
        }
    }
}
