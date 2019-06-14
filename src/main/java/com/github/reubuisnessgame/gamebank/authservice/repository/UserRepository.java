package com.github.reubuisnessgame.gamebank.authservice.repository;

import com.github.reubuisnessgame.gamebank.authservice.model.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserModel, Long> {
    Optional<UserModel> findByUsername(String number);
}
