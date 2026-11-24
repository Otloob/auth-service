package org.spring.authservice.repository;

import org.spring.authservice.entity.PasswordCredential;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordCredentialRepository extends JpaRepository<PasswordCredential, Long> {
}
