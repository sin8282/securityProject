package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.ResourceRepository;
import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourceRepository resourceRepository){
        SecurityResourceService securityResourceService = new SecurityResourceService(resourceRepository);
        return securityResourceService;
    }
}
