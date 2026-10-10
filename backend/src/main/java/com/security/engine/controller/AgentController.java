package com.security.engine.controller;

import com.security.engine.model.AgentConversation;
import com.security.engine.service.AgentChatService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/agent")
@RequiredArgsConstructor
public class AgentController {

    private final AgentChatService agentChatService;

    @PostMapping("/audit")
    public AgentConversation triggerAudit(@RequestBody AuditRequest request) {
        return agentChatService.runAutonomousAudit(request.getTarget(), request.getPrompt());
    }

    @PostMapping("/chat")
    public AgentConversation chat(@RequestBody ChatRequest request) {
        return agentChatService.chat(request.getSessionId(), request.getMessage(), request.getTarget());
    }

    @GetMapping("/conversations/{sessionId}")
    public AgentConversation getConversation(@PathVariable String sessionId) {
        return agentChatService.getConversationBySessionId(sessionId);
    }

    @GetMapping("/conversations")
    public List<AgentConversation> listConversations() {
        return agentChatService.getAllConversations();
    }

    @Data
    public static class AuditRequest {
        private String target;
        private String prompt;
    }

    @Data
    public static class ChatRequest {
        private String sessionId;
        private String message;
        private String target;
    }
}
