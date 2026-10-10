package com.security.engine.client;

import com.security.engine.client.dto.EngineDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class FastApiClient {

    private final WebClient fastapiWebClient;

    public Mono<Map<String, String>> checkHealth() {
        return fastapiWebClient.get()
                .uri("/health")
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
                .doOnError(ex -> log.error("Failed to check engine health: {}", ex.getMessage()));
    }

    public Mono<List<ScannerMetadataDto>> listScanners() {
        return fastapiWebClient.get()
                .uri("/api/v1/scanners")
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(new ParameterizedTypeReference<List<ScannerMetadataDto>>() {})
                .doOnError(ex -> log.error("Failed to list scanners: {}", ex.getMessage()));
    }

    public Mono<List<EndpointDto>> discoverEndpoints(String targetUrl) {
        DiscoverRequest request = new DiscoverRequest(targetUrl);
        return fastapiWebClient.post()
                .uri("/api/v1/discover")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(new ParameterizedTypeReference<List<EndpointDto>>() {})
                .doOnError(ex -> log.error("Failed discovery on {}: {}", targetUrl, ex.getMessage()));
    }

    public Mono<ScanResponse> executeOneShotScan(ScanRequest request) {
        return fastapiWebClient.post()
                .uri("/api/v1/scan")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(ScanResponse.class)
                .doOnError(ex -> log.error("Failed one-shot scan on {}: {}", request.target(), ex.getMessage()));
    }

    public Mono<SessionCreateResponse> createSession(SessionCreateRequest request) {
        return fastapiWebClient.post()
                .uri("/api/v1/sessions")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(SessionCreateResponse.class)
                .doOnError(ex -> log.error("Failed to create session on {}: {}", request.target(), ex.getMessage()));
    }

    public Mono<SessionDiscoverResponse> triggerSessionDiscover(String sessionId) {
        return fastapiWebClient.post()
                .uri("/api/v1/sessions/{sessionId}/discover", sessionId)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(SessionDiscoverResponse.class)
                .doOnError(ex -> log.error("Failed session discover on {}: {}", sessionId, ex.getMessage()));
    }

    public Mono<SessionScanResponse> triggerSessionScan(String sessionId, List<String> scanners) {
        SessionScanRequest request = new SessionScanRequest(scanners);
        return fastapiWebClient.post()
                .uri("/api/v1/sessions/{sessionId}/scan", sessionId)
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(SessionScanResponse.class)
                .doOnError(ex -> log.error("Failed session scan on {}: {}", sessionId, ex.getMessage()));
    }

    public Mono<Map<String, Object>> getSession(String sessionId) {
        return fastapiWebClient.get()
                .uri("/api/v1/sessions/{sessionId}", sessionId)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .doOnError(ex -> log.error("Failed to get session {}: {}", sessionId, ex.getMessage()));
    }

    public Mono<Map<String, String>> deleteSession(String sessionId) {
        return fastapiWebClient.delete()
                .uri("/api/v1/sessions/{sessionId}", sessionId)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
                .doOnError(ex -> log.error("Failed to delete session {}: {}", sessionId, ex.getMessage()));
    }

    public Mono<AgentResponse> runAgent(AgentRunRequest request) {
        return fastapiWebClient.post()
                .uri("/api/v1/agent/run")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(AgentResponse.class)
                .doOnError(ex -> log.error("Failed agent run on {}: {}", request.target(), ex.getMessage()));
    }

    public Mono<AgentResponse> chatWithAgent(AgentChatRequest request) {
        return fastapiWebClient.post()
                .uri("/api/v1/agent/chat")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class)
                                .flatMap(err -> Mono.error(new ResponseStatusException(resp.statusCode(), err))))
                .bodyToMono(AgentResponse.class)
                .doOnError(ex -> log.error("Failed agent chat on session {}: {}", request.sessionId(), ex.getMessage()));
    }
}
