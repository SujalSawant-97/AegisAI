package com.security.engine.service;

import com.security.engine.model.TargetApp;
import com.security.engine.repository.TargetAppRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.List;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class TargetService {

    private final TargetAppRepository targetRepository;

    private static final Set<String> ALLOWED_LOCAL_HOSTS = Set.of(
            "localhost", "127.0.0.1", "::1", "[::1]"
    );

    private boolean isAllowedHost(String host) {
        if (host == null) {
            return false;
        }
        String h = host.toLowerCase();
        return ALLOWED_LOCAL_HOSTS.contains(h)
                || h.equals("host.docker.internal")
                || h.endsWith(".internal")
                || h.endsWith(".local")
                || !h.contains("."); // Docker container service names (e.g. vulnerable-app, juice-shop)
    }

    public TargetApp registerTarget(TargetApp target) {
        validateTargetUrl(target.getBaseUrl());

        targetRepository.findByBaseUrl(target.getBaseUrl()).ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Target application with baseUrl '" + target.getBaseUrl() + "' already exists.");
        });

        if (target.getName() == null || target.getName().isBlank()) {
            target.setName(target.getBaseUrl());
        }

        TargetApp saved = targetRepository.save(target);
        log.info("Registered new target application: id={}, url={}", saved.getId(), saved.getBaseUrl());
        return saved;
    }

    public List<TargetApp> getAllTargets() {
        return targetRepository.findAll();
    }

    public TargetApp getTargetById(String id) {
        return targetRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target not found: " + id));
    }

    public TargetApp getTargetByBaseUrl(String baseUrl) {
        return targetRepository.findByBaseUrl(baseUrl)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target not found for url: " + baseUrl));
    }

    public TargetApp updateTarget(String id, TargetApp updated) {
        TargetApp existing = getTargetById(id);

        if (updated.getName() != null && !updated.getName().isBlank()) {
            existing.setName(updated.getName());
        }
        if (updated.getDescription() != null) {
            existing.setDescription(updated.getDescription());
        }
        if (updated.getAuthToken() != null) {
            existing.setAuthToken(updated.getAuthToken());
        }
        if (updated.getLowPrivToken() != null) {
            existing.setLowPrivToken(updated.getLowPrivToken());
        }
        if (updated.getDefaultHeaders() != null) {
            existing.setDefaultHeaders(updated.getDefaultHeaders());
        }

        return targetRepository.save(existing);
    }

    public void deleteTarget(String id) {
        TargetApp existing = getTargetById(id);
        targetRepository.delete(existing);
        log.info("Deleted target application: id={}", id);
    }

    public void validateTargetUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Target URL must not be blank.");
        }
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null || !isAllowedHost(host)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Target host '" + host + "' is not a permitted local or container address.");
            }
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Scheme must be http or https.");
            }
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid URL format: " + e.getMessage());
        }
    }
}
