package io.korner.securecapita.repository;

import io.korner.securecapita.domain.User;
import io.korner.securecapita.dto.UserDTO;

import java.util.Collection;

public interface UserRepository <T extends User> {
    /* Basic CRUD Operations */

    T create(T data);
    Collection<T> list(int page, int pageSize);
    T update(T data);
    Boolean delete(Long id);

    T getUserByEmail(String email);

    void sendVerificationCode(UserDTO user);

    T verifyCode(String email, String code);

    void resetPassword(String email);

    T verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    T verifyAccountKey(String key);

    /* More Complex Operations */
}
