package io.korner.securecapita.service.implementation;

import io.korner.securecapita.domain.Role;
import io.korner.securecapita.repository.RoleRepository;
import io.korner.securecapita.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final RoleRepository<Role> repository;
    @Override
    public Role getRoleByUserId(Long id) {
        return repository.getRoleByUserId(id);
    }
}
