package io.security.corespringsecurity.service;

import org.springframework.transaction.annotation.Transactional;

public interface RoleHierarchyService {
    String findAllHierarchy();
}
