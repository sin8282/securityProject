package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.factory.MethodResourcesFactoryBean;
import io.security.corespringsecurity.security.filter.CustomMethodSecurityInterceptor;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.corespringsecurity.security.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

import java.sql.CallableStatement;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Order(3)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    @Autowired
    private SecurityResourceService securityResourceService;

    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return mapBasedMethodSecurityMetadataSource();
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
    }

    @Bean
    public MethodResourcesFactoryBean methodResourcesMapFactoryBean() {
        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("method");
        return methodResourcesFactoryBean;
    }

    @Bean
    public MethodResourcesFactoryBean pointResourcesMapFactoryBean() {
        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("pointcut");
        return methodResourcesFactoryBean;
    }

    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor(){
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointResourcesMapFactoryBean().getObject());
        return protectPointcutPostProcessor;
    }

    @Override
    protected AccessDecisionManager accessDecisionManager() {
        AffirmativeBased affirmativeBased = (AffirmativeBased)super.accessDecisionManager();
        List<AccessDecisionVoter<?>> decisionVoters = affirmativeBased.getDecisionVoters();
        for(AccessDecisionVoter accessDecisionVoter : decisionVoters){
            if(accessDecisionVoter instanceof RoleVoter){
                decisionVoters.remove(accessDecisionVoter);
            }
        }
        decisionVoters.add(0,roleVoter());
        return affirmativeBased;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        return roleHierarchyVoter;
    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }


//    @Bean
//    @Profile("pointcut")
//    BeanPostProcessor protectPointcutPostProcessor() throws Exception {
//
//        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
//        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
//        declaredConstructor.setAccessible(true);
//        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
//        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
//        setPointcutMap.setAccessible(true);
//        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());
//
//        return (BeanPostProcessor)instance;
//    }

}
