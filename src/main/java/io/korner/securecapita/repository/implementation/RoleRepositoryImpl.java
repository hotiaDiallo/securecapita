package io.korner.securecapita.repository.implementation;

import io.korner.securecapita.domain.Role;
import io.korner.securecapita.exceptions.ApiException;
import io.korner.securecapita.repository.RoleRepository;
import io.korner.securecapita.rowmapper.RoleRowMapper;
import io.korner.securecapita.rowmapper.UserRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

import static io.korner.securecapita.enumerations.RoleType.ROLE_USER;
import static io.korner.securecapita.query.RoleQuery.*;
import static io.korner.securecapita.query.UserQuery.SELECT_USER_BY_EMAIL_QUERY;

@Repository
@RequiredArgsConstructor
@Slf4j
public class RoleRepositoryImpl implements RoleRepository<Role> {
    private final NamedParameterJdbcTemplate jdbcTemplate;

    @Override
    public Role create(Role data) {
        return null;
    }

    @Override
    public Collection<Role> list(int page, int pageSize) {
        return null;
    }

    @Override
    public Role update(Role data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

    @Override
    public void addRoleToUser(Long userId, String roleName) {
        log.info("Adding role {} to user id: {}", roleName, userId);
        try {
            Role role = jdbcTemplate.queryForObject(SELECT_ROLE_BY_NAME_QUERY, Map.of("roleName", roleName), new RoleRowMapper());
            jdbcTemplate.update(INSERT_ROLE_TO_USER_QUERY, Map.of("userId", userId, "roleId", Objects.requireNonNull(role).getId()));
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("No role found by name: " + ROLE_USER.name());
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public Role getRoleByUserId(Long userId) {
        log.info("Getting role for user ID: {}", userId);
        try {
            return jdbcTemplate.queryForObject(SELECT_ROLE_BY_USER_ID_QUERY, Map.of("userId", userId), new RoleRowMapper());
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("No role found by ID: " + userId);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public Role getRoleByUserEmail(String userEmail) {
        log.info("Getting role for user email: {}", userEmail);
        try {
           return jdbcTemplate.queryForObject(SELECT_ROLE_BY_USER_EMAIL_QUERY, Map.of("email", userEmail), new RoleRowMapper());
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("No role found by email: " + userEmail);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public void updateUserRole(Long userId, String roleName) {

    }
}
