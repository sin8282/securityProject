package io.security.corespringsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.PostConstruct;

@SpringBootApplication
public class CoreSpringSecurityApplication {
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JdbcTemplate jdbcTemplate;
    @PostConstruct
    public void init(){
/*        String pwd = passwordEncoder.encode("1");
        jdbcTemplate.execute("INSERT INTO account (age, email, password, role, username, id) VALUES ('1','sweetejr777@gmail.com','"
                + pwd
                + "', 'ROLE_USER', 'user',next value for hibernate_sequence)");
        jdbcTemplate.execute("INSERT INTO account (age, email, password, role, username, id) VALUES ('1','sweetejr777@gmail.com','"
                + pwd
                + "', 'ROLE_MANAGER', 'manager',next value for hibernate_sequence)");*/
    }

    public static void main(String[] args) {

        SpringApplication.run(CoreSpringSecurityApplication.class, args);
    }

}
