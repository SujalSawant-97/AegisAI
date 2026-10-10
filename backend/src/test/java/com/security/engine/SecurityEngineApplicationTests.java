package com.security.engine;

import com.security.engine.model.Severity;
import com.security.engine.model.TargetApp;
import com.security.engine.service.TargetService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SecurityEngineApplicationTests {

    @Mock
    private com.security.engine.repository.TargetAppRepository targetRepository;

    private TargetService targetService;

    @BeforeEach
    void setUp() {
        targetService = new TargetService(targetRepository);
    }

    @Test
    void testValidLocalTarget() {
        assertDoesNotThrow(() -> targetService.validateTargetUrl("http://localhost:8080"));
        assertDoesNotThrow(() -> targetService.validateTargetUrl("http://127.0.0.1:3000"));
        assertDoesNotThrow(() -> targetService.validateTargetUrl("https://localhost:8443/api"));
    }

    @Test
    void testDisallowedExternalTarget() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                targetService.validateTargetUrl("http://google.com"));
        assertTrue(ex.getMessage().contains("not a permitted local address"));
    }

    @Test
    void testSeverityEnum() {
        assertEquals("CRITICAL", Severity.CRITICAL.name());
        assertEquals(5, Severity.values().length);
    }

    @Test
    void testTargetAppBuilder() {
        TargetApp app = TargetApp.builder()
                .name("Test App")
                .baseUrl("http://localhost:8080")
                .description("Sample description")
                .build();
        assertEquals("Test App", app.getName());
        assertEquals("http://localhost:8080", app.getBaseUrl());
    }
}
