package com.connect11.server.domain.user.entity;

import com.connect11.server.global.common.BaseTimeEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(name = "student_number", nullable = false, unique = true, length = 20)
    private String studentNumber;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status;

    private User(String email, String passwordHash, String name, String studentNumber, Role role) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.name = name;
        this.studentNumber = studentNumber;
        this.role = role;
        this.status = UserStatus.ACTIVE;
    }

    public static User createStudent(String email, String passwordHash, String name, String studentNumber) {
        return new User(email, passwordHash, name, studentNumber, Role.STUDENT);
    }

    public static User createAdmin(String email, String passwordHash, String name, String studentNumber) {
        return new User(email, passwordHash, name, studentNumber, Role.ADMIN);
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE;
    }

    public void changePassword(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
    }
}
