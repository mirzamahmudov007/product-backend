package com.uz.productbackend.system;
import com.uz.productbackend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface UserRepository extends JpaRepository<User , Long> {

    User findByUsername(String username);

    Boolean existsByUsername(String username);


}
