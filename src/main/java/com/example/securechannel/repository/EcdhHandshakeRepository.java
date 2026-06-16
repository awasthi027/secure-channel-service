package com.example.securechannel.repository;

import com.example.securechannel.entity.EcdhHandshakeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EcdhHandshakeRepository extends JpaRepository<EcdhHandshakeEntity, String> {
}

