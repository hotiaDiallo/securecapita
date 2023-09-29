package io.korner.securecapita.service;

import io.korner.securecapita.domain.User;
import io.korner.securecapita.dto.UserDTO;

public interface UserService {
    UserDTO createUser(User user);
    UserDTO getUserByEmail(String email);

    void sendVerificationCode(UserDTO user);

    UserDTO verifyCode(String email, String code);

    void resetPassword(String email);

    UserDTO verifyPasswordUrlKey(String key);
}
