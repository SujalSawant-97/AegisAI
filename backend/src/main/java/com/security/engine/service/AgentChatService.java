package com.security.engine.service;

import com.security.engine.client.FastApiClient;
import com.security.engine.client.dto.EngineDtos.*;
import com.security.engine.model.AgentConversation;
import com.security.engine.repository.AgentConversationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AgentChatService {

    private final FastApiClient fastApiClient;
    private final AgentConversationRepository conversationRepository;
    private final TargetService targetService;

    public AgentConversation runAutonomousAudit(String targetUrl, String prompt) {
        targetService.validateTargetUrl(targetUrl);

        String sessionId = "THREAD-" + UUID.randomUUID().toString().substring(0, 10);
        String finalPrompt = (prompt != null && !prompt.isBlank())
                ? prompt
                : "Perform a comprehensive security audit of " + targetUrl;

        AgentRunRequest request = new AgentRunRequest(targetUrl, finalPrompt, sessionId);
        log.info("Starting autonomous agent audit on {} with session {}", targetUrl, sessionId);

        AgentResponse response = fastApiClient.runAgent(request).block();
        if (response == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Empty response from agent service.");
        }

        List<AgentConversation.AgentMessage> messages = new ArrayList<>();
        messages.add(AgentConversation.AgentMessage.builder()
                .role("user")
                .content(finalPrompt)
                .timestamp(Instant.now())
                .build());
        messages.add(AgentConversation.AgentMessage.builder()
                .role("assistant")
                .content(response.response())
                .timestamp(Instant.now())
                .build());

        AgentConversation conversation = AgentConversation.builder()
                .sessionId(response.sessionId())
                .targetUrl(targetUrl)
                .initialPrompt(finalPrompt)
                .messages(messages)
                .totalMessagesCount(messages.size())
                .build();

        return conversationRepository.save(conversation);
    }

    public AgentConversation chat(String sessionId, String message, String targetUrl) {
        if (message == null || message.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message must not be empty.");
        }

        String threadId = (sessionId != null && !sessionId.isBlank())
                ? sessionId
                : "THREAD-" + UUID.randomUUID().toString().substring(0, 10);

        AgentConversation conversation = conversationRepository.findBySessionId(threadId)
                .orElseGet(() -> AgentConversation.builder()
                        .sessionId(threadId)
                        .targetUrl(targetUrl)
                        .initialPrompt(message)
                        .messages(new ArrayList<>())
                        .build());

        AgentChatRequest request = new AgentChatRequest(message, targetUrl, threadId);
        log.info("Dispatching chat message to session {}", threadId);

        AgentResponse response = fastApiClient.chatWithAgent(request).block();
        if (response == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Empty response from agent chat.");
        }

        conversation.getMessages().add(AgentConversation.AgentMessage.builder()
                .role("user")
                .content(message)
                .timestamp(Instant.now())
                .build());

        conversation.getMessages().add(AgentConversation.AgentMessage.builder()
                .role("assistant")
                .content(response.response())
                .timestamp(Instant.now())
                .build());

        conversation.setTotalMessagesCount(conversation.getMessages().size());
        return conversationRepository.save(conversation);
    }

    public AgentConversation getConversationBySessionId(String sessionId) {
        return conversationRepository.findBySessionId(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Conversation not found: " + sessionId));
    }

    public List<AgentConversation> getAllConversations() {
        return conversationRepository.findAllByOrderByCreatedAtDesc();
    }
}
