package io.korner.securecapita.repository.implementation;

import io.korner.securecapita.domain.Role;
import io.korner.securecapita.domain.User;
import io.korner.securecapita.domain.UserPrincipal;
import io.korner.securecapita.dto.UserDTO;
import io.korner.securecapita.enumerations.VerificationType;
import io.korner.securecapita.exceptions.ApiException;
import io.korner.securecapita.repository.RoleRepository;
import io.korner.securecapita.repository.UserRepository;
import io.korner.securecapita.rowmapper.UserRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static io.korner.securecapita.contants.Constants.EMAIL_ALREADY_USE_MESSAGE;
import static io.korner.securecapita.enumerations.RoleType.ROLE_USER;
import static io.korner.securecapita.enumerations.VerificationType.ACCOUNT;
import static io.korner.securecapita.enumerations.VerificationType.PASSWORD;
import static io.korner.securecapita.query.TwoFactorVerificationsQuery.SELECT_CODE_EXPIRATION_QUERY;
import static io.korner.securecapita.query.UserQuery.*;
import static java.util.Objects.requireNonNull;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepository<User>, UserDetailsService {
    private static final String DATE_FORMAT = "yyyy-MM-dd hh:mm:ss";
    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final RoleRepository<Role> roleRepository;
    private final BCryptPasswordEncoder encoder;

    @Override
    public User create(User user) {
        if(emailAlreadyExists(user.getEmail()))
            throw new ApiException(EMAIL_ALREADY_USE_MESSAGE);
        try {
            GeneratedKeyHolder keyHolder = new GeneratedKeyHolder();
            SqlParameterSource sqlParameterSource = getSqlParameterSource(user);
            jdbcTemplate.update(INSERT_USER_QUERY, sqlParameterSource, keyHolder);
            user.setId(requireNonNull(keyHolder.getKey()).longValue());
            roleRepository.addRoleToUser(user.getId(), ROLE_USER.name());

            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), ACCOUNT.getType());
            jdbcTemplate.update(INSERT_ACCOUNT_VERIFICATION_URL_QUERY, Map.of("userId", user.getId(), "url", verificationUrl));

            //emailService.sendVerificationUrl(user.getFirstName(), user.getEmail(), verificationUrl, ACCOUNT);

            user.setEnabled(true);
            user.setNotLocked(true);
            return user;
        } catch (Exception exception) {
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public Collection<User> list(int page, int pageSize) {
        return null;
    }

    @Override
    public User update(User data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = getUserByEmail(email);
        if (user == null){
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        }
        log.info("User found in the database: {}", email);
        return new UserPrincipal(user, roleRepository.getRoleByUserId(user.getId()));
    }

    @Override
    public User getUserByEmail(String email) {
        try {
            return jdbcTemplate.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
        }catch (EmptyResultDataAccessException exception) {
            log.error(exception.getMessage());
            throw new ApiException("No user found by email: "+ email);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        String expirationDate = DateFormatUtils.format(DateUtils.addDays(new Date(), 1), DATE_FORMAT);
        String verificationCode = RandomStringUtils.randomAlphabetic(8).toUpperCase();
        try {
            jdbcTemplate.update(DELETE_VERIFICATION_CODE_BY_USER_ID_QUERY, Map.of("userId", user.getId()));
            jdbcTemplate.update(INSERT_VERIFICATION_CODE_QUERY, Map.of("userId", user.getId(), "code", verificationCode, "expirationDate", expirationDate));
            log.info("Verification code: {}", verificationCode);
            //SmsUtils.sendSMS(user.getPhone(), "From: SecureCapita\nVerification code\n" +verificationCode);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public User verifyCode(String email, String code) {
        try {
            if(isVerificatonCodeExpired(code))
                throw new ApiException("This code has expired. Please login again.");
            User userByEmail = jdbcTemplate.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
            User userByCode = jdbcTemplate.queryForObject(SELECT_USER_BY_USER_CODE_QUERY, Map.of("code", code), new UserRowMapper());
            if (userByCode == null || !userByCode.getEmail().equalsIgnoreCase(userByEmail.getEmail()))
                throw new ApiException("Code is invalid. Please try again");
            jdbcTemplate.update(DELETE_CODE_QUERY, Map.of("code", code));
            return userByCode;
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("Could not find record");
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurs. Please try again.");
        }
    }

    @Override
    public void resetPassword(String email) {
        if(!emailAlreadyExists(email))
            throw new ApiException("There is no account for this email address");
        try {
            String expirationDate = DateFormatUtils.format(DateUtils.addDays(new Date(), 1), DATE_FORMAT);
            User user = getUserByEmail(email);
            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), PASSWORD.getType());
            jdbcTemplate.update(DELETE_PASSWORD_VERIFICATION_BY_USER_ID_QUERY, Map.of("userId", user.getId()));
            jdbcTemplate.update(INSERT_PASSWORD_VERIFICATION_QUERY, Map.of("userId", user.getId(), "url", verificationUrl, "expirationDate", expirationDate));
            // TODO send email with url to user
            log.info("Verification URL: {}", verificationUrl);
        }catch (Exception exception){
            throw new ApiException("An error occurs. Please try again.");
        }
    }

    @Override
    public User verifyPasswordKey(String key) {
        if(isLinkExpired(key, PASSWORD))
            throw new ApiException("This link has expired. Please reset your password again.");
        try {
            User user = jdbcTemplate.queryForObject(SELECT_USER_BY_PASSWORD_URL_QUERY, Map.of("url", getVerificationUrl(key, PASSWORD.getType())), new UserRowMapper());
            //jdbcTemplate.update(DELETE_USER_FROM_PASSWORD_VERIFICATION_QUERY, Map.of("userId", user.getId())); // Depends on the business or use case
            return user;
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException("This link is not valid. Please reset your password again");
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurs. Please try again.");
        }
    }

    private boolean isLinkExpired(String key, VerificationType verificationType) {
        try {
            return Boolean.TRUE.equals(jdbcTemplate.queryForObject(SELECT_EXPIRATION_BY_URL_QUERY, Map.of("url", getVerificationUrl(key, verificationType.getType())), Boolean.class));
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException("This link is not valid. Please reset your password again");
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurs. Please try again.");
        }
    }

    private boolean emailAlreadyExists(String email) {
        return getEmailCount(email.trim().toLowerCase()) > 0;
    }

    private boolean isVerificatonCodeExpired(String code) {
        try {
            return Boolean.TRUE.equals(jdbcTemplate.queryForObject(SELECT_CODE_EXPIRATION_QUERY, Map.of("code", code), Boolean.class));
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("This code is not valid");
        }catch (Exception exception){
            throw new ApiException("An error occurs. Please try again.");
        }
    }

    private SqlParameterSource getSqlParameterSource(User user) {
        return new MapSqlParameterSource()
                .addValue("firstName", user.getFirstName())
                .addValue("lastName", user.getLastName())
                .addValue("email", user.getEmail())
                .addValue("password", encoder.encode(user.getPassword()));
    }

    private Integer getEmailCount(String email) {
        return jdbcTemplate.queryForObject(COUNT_USER_EMAIL_QUERY, Map.of("email", email), Integer.class);
    }
    private String getVerificationUrl(String key, String type){
        return ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/user/verify/" + type + "/" + key)
                .toUriString();
    }
}
