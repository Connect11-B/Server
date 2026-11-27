package com.connect11.server.domain.user.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.config.AppProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class AdminAccountInitializerTest {

    private static final String PASSWORD = "AdminPassword123";

    private UserRepository userRepository;
    private PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        encoder = new BCryptPasswordEncoder(4);
    }

    private AdminAccountInitializer initializer(AppProperties.Admin admin) {
        return new AdminAccountInitializer(new AppProperties(null, null, null, null, admin), userRepository, encoder);
    }

    @Test
    void 설정이_없거나_비어_있으면_아무것도_하지_않는다() {
        initializer(null).run(null);
        initializer(new AppProperties.Admin("", "", "관리자")).run(null);
        initializer(new AppProperties.Admin("admin@school.kr", "  ", "관리자")).run(null);
        initializer(new AppProperties.Admin(null, PASSWORD, "관리자")).run(null);

        verifyNoInteractions(userRepository);
    }

    @Test
    void 계정이_없으면_ADMIN으로_생성하고_비밀번호는_해시로_저장한다() {
        when(userRepository.existsByEmail("admin@school.kr")).thenReturn(false);

        initializer(new AppProperties.Admin(" Admin@School.kr ", PASSWORD, " 운영자 ")).run(null);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getRole()).isEqualTo(Role.ADMIN);
        assertThat(saved.getEmail()).isEqualTo("admin@school.kr");
        assertThat(saved.getName()).isEqualTo("운영자");
        assertThat(saved.getStudentNumber()).startsWith("ADMIN-").hasSize(18);
        assertThat(saved.getStudentNumber()).isEqualTo(AdminAccountInitializer.adminStudentNumber("admin@school.kr"));
        assertThat(saved.isActive()).isTrue();
        assertThat(saved.getPasswordHash()).isNotEqualTo(PASSWORD);
        assertThat(encoder.matches(PASSWORD, saved.getPasswordHash())).isTrue();
    }

    @Test
    void 이미_있는_계정은_덮어쓰지_않는다() {
        when(userRepository.existsByEmail("admin@school.kr")).thenReturn(true);

        initializer(new AppProperties.Admin("admin@school.kr", PASSWORD, "관리자")).run(null);

        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 비밀번호가_정책을_어기면_서버_시작을_실패시키고_메시지에_비밀번호가_없다() {
        String weak = "weak";

        assertThatThrownBy(() -> initializer(new AppProperties.Admin("admin@school.kr", weak, "관리자")).run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ADMIN_PASSWORD")
                .hasMessageNotContaining(weak + "\"");
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 이메일_형식이_틀리면_서버_시작을_실패시킨다() {
        assertThatThrownBy(() -> initializer(new AppProperties.Admin("not-an-email", PASSWORD, "관리자")).run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ADMIN_EMAIL");
    }

    @Test
    void 다른_인스턴스가_먼저_만들었으면_조용히_넘어간다() {
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(new DataIntegrityViolationException("dup"));

        assertThatCode(() -> initializer(new AppProperties.Admin("admin@school.kr", PASSWORD, "관리자")).run(null))
                .doesNotThrowAnyException();
    }
}
