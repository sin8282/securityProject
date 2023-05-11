package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resource;

import java.util.List;

public interface ResourceService {

    Resource getResource(long id);

    List<Resource> getResource();

    void createResource(Resource Resources);

    void deleteResource(long id);
}