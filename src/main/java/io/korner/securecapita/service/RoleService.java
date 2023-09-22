package io.korner.securecapita.service;

import io.korner.securecapita.domain.Role;

public interface RoleService {
    Role getRoleByUserId(Long id);
}
