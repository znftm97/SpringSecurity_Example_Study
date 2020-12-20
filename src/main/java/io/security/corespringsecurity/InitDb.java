package io.security.corespringsecurity;

import io.security.corespringsecurity.domain.Account;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import javax.persistence.EntityManager;

@Component
@RequiredArgsConstructor
public class InitDb {

    private final InitService initService;

    @PostConstruct
    public void init(){
        initService.init1();
    }

    @Component
    @Transactional
    @RequiredArgsConstructor
    static class InitService{

        private final EntityManager em;
        private final PasswordEncoder passwordEncoder;


        public void init1(){
            Account account = createAccount("user", "26", "znftm97@naver.com", "1111", "ROLE_USER");
            em.persist(account);
        }
        private Account createAccount(String name, String age, String email, String password, String role){
            Account account = new Account();

            account.setUsername(name);
            account.setAge(age);
            account.setEmail(email);
            account.setPassword(passwordEncoder.encode(password));
            account.setRole(role);

            em.persist(account);

            return account;
        }
    }

}
