package io.korner.securecapita.service.implementation;

import io.korner.securecapita.domain.User;
import io.korner.securecapita.dto.UserDTO;
import io.korner.securecapita.dtomapper.UserDTOMapper;
import io.korner.securecapita.repository.UserRepository;
import io.korner.securecapita.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository<User> repository;

    @Override
    public UserDTO createUser(User user) {
        return UserDTOMapper.fromUser(repository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return UserDTOMapper.fromUser(repository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        repository.sendVerificationCode(user);
    }

    @Override
    public User getUser(String email) {
        return repository.getUserByEmail(email);
    }
}
