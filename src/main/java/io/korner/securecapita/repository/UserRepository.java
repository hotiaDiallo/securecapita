package io.korner.securecapita.repository;

import io.korner.securecapita.domain.User;

import java.util.Collection;

public interface UserRepository <T extends User> {
    /* Basic CRUD Operations */

    T create(T data);
    Collection<T> list(int page, int pageSize);
    T update(T data);
    Boolean delete(Long id);

    T getUserByEmail(String email);

    /* More Complex Operations */
}
