package io.korner.securecapita.repository;
import io.korner.securecapita.domain.Role;

import java.util.Collection;

public interface RoleRepository <T extends Role> {
    /* Basic CRUD Operations */

    T create(T data);
    Collection<T> list(int page, int pageSize);
    T update(T data);
    Boolean delete(Long id);

    /* More Complex Operations */
    void addRoleToUser(Long userId, String roleName);
    Role getRoleByUserId(Long userId);
    Role getRoleByUserEmail(String userEmail);
    void updateUserRole(Long userId, String roleName);
}
