package com.security.engine.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "agent_conversations")
public class AgentConversation {

    @Id
    private String id;

    @Indexed(unique = true)
    private String sessionId; // thread_id in LangGraph

    @Indexed
    private String targetUrl;

    private String initialPrompt;

    @Builder.Default
    private List<AgentMessage> messages = new ArrayList<>();

    private int totalMessagesCount;

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AgentMessage {
        private String role; // "user" or "assistant"
        private String content;
        @Builder.Default
        private Instant timestamp = Instant.now();
    }
}
