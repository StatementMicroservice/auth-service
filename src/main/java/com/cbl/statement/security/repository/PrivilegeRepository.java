package com.cbl.statement.security.repository;

import com.cbl.statement.security.entity.Privilege;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege, Long> {
    Optional<Privilege> findByName(String privilege);

    @Query(value = "SELECT p.name FROM privilege p " +
                           "INNER JOIN roles_privileges rp ON p.Id = rp.PrivilegeId " +
                           "INNER JOIN role r ON rp.RoleId = r.Id WHERE r.Name = :roleName ", nativeQuery = true)
    Optional<Collection<String>> findPrivilegesByRoleName(String roleName);

    Collection<Privilege> findAllByNameIn(List<String> privileges);
}
