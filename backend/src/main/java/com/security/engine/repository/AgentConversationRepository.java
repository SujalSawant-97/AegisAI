package com.security.engine.repository;

import com.security.engine.model.AgentConversation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AgentConversationRepository extends MongoRepository<AgentConversation, String> {

    Optional<AgentConversation> findBySessionId(String sessionId);

    List<AgentConversation> findByTargetUrlOrderByCreatedAtDesc(String targetUrl);

    List<AgentConversation> findAllByOrderByCreatedAtDesc();
}
