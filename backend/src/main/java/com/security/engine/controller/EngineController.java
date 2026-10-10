package com.security.engine.controller;

import com.security.engine.client.FastApiClient;
import com.security.engine.client.dto.EngineDtos.ScannerMetadataDto;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/engine")
@RequiredArgsConstructor
public class EngineController {

    private final FastApiClient fastApiClient;

    @GetMapping("/health")
    public Map<String, String> getEngineHealth() {
        return fastApiClient.checkHealth().block();
    }

    @GetMapping("/scanners")
    public List<ScannerMetadataDto> getAvailableScanners() {
        return fastApiClient.listScanners().block();
    }
}
