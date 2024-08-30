package com.cbl.statement.security.config.userconfig;


import com.cbl.statement.security.entity.Privilege;
import com.cbl.statement.security.entity.Role;
import com.cbl.statement.security.entity.User;
import com.cbl.statement.security.repository.PrivilegeRepository;
import com.cbl.statement.security.repository.RoleRepository;
import com.cbl.statement.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class InitialUserInfo implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PrivilegeRepository privilegeRepository;
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
       /* User manager = new User();
        manager.setUserName("Manager");
        manager.setPassword(passwordEncoder.encode("password"));
        manager.setRoles("ROLE_MANAGER");
        manager.setEmailId("manager@manager.com");

        User admin = new User();
        admin.setUserName("Admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setRoles("ROLE_ADMIN");
        admin.setEmailId("admin@admin.com");

        User user = new User();
        user.setUserName("User");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRoles("ROLE_USER");
        user.setEmailId("user@user.com");

        userInfoRepo.saveAll(List.of(manager,admin,user));*/

        Privilege readPrivilege = createPrivilegeIfNotFound("READ");
        Privilege writePrivilege = createPrivilegeIfNotFound("WRITE");
        Privilege deletePrivilege = createPrivilegeIfNotFound("DELETE");

        List<Privilege> adminPrivileges = Arrays.asList(readPrivilege, writePrivilege, deletePrivilege);
        List<Privilege> managerPrivileges = Arrays.asList(readPrivilege, writePrivilege);
        List<Privilege> userPrivileges = Collections.singletonList(readPrivilege);

        createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);
        createRoleIfNotFound("ROLE_MANAGER", managerPrivileges);
        createRoleIfNotFound("ROLE_USER", userPrivileges);

        Role managerRole = roleRepository.findByName("ROLE_MANAGER")
                                         .orElseThrow(() -> new RuntimeException(String.format("Role: %s not found", "ROLE_ADMIN")));

        User user = new User();
        user.setFirstName("Mr.");
        user.setLastName("Manager");
        user.setUserName("Manager");
        user.setEmail("manager@manager.com");
        user.setPassword(passwordEncoder.encode("password"));
        user.setMobile("01746565656");
        user.setEnabled(true);
        user.setRoles(Collections.singletonList(managerRole));
        userRepository.save(user);
    }

    private Privilege createPrivilegeIfNotFound(String name) {

        final Privilege privilegeToBeSavedInDB = new Privilege();
        final Optional<Privilege> privilege = privilegeRepository.findByName(name);

        if (privilege.isEmpty()) {
            privilegeToBeSavedInDB.setName(name);
            privilegeRepository.save(privilegeToBeSavedInDB);
        }
        return privilegeToBeSavedInDB;
    }

    private void createRoleIfNotFound(String name, Collection<Privilege> privileges) {

        final Role roleToBeSavedInDB = new Role();
        final Optional<Role> role = roleRepository.findByName(name);

        if (role.isEmpty()) {
            roleToBeSavedInDB.setName(name);
            roleToBeSavedInDB.setPrivileges(privileges);
            roleRepository.save(roleToBeSavedInDB);
        }
    }
}
