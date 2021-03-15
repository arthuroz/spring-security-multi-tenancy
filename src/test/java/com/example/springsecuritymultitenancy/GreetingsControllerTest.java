package com.example.springsecuritymultitenancy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(GreetingsController.class)
@Import(SecurityConfiguration.class)
@MockBean(JwtAuthenticationManagerIssuerResolver.class)
class GreetingsControllerTest {
    @Autowired private MockMvc mockMvc;

    @Nested
    class GetGreetings {
        @Test
        @WithAnonymousUser
        void denyAnonymous() throws Exception {
            mockMvc.perform(get("/")).andExpect(status().isUnauthorized());
        }

        @Test
        @WithMockUser(authorities = "read:greetings")
        void whenHasReadScopeThenGreet() throws Exception {
            mockMvc.perform(get("/")).andExpect(status().isOk());
        }

        @Test
        @WithMockUser(authorities = "write:greetings")
        void whenHasWriteScopeThenGreet() throws Exception {
            mockMvc.perform(get("/")).andExpect(status().isOk());
        }

        @Test
        @WithMockUser(authorities = "random")
        void whenHasWrongScopeThenDeny() throws Exception {
            mockMvc.perform(get("/")).andExpect(status().isForbidden());
        }
    }

    @Nested
    class PostGreetings {
        @Test
        @WithAnonymousUser
        void denyAnonymous() throws Exception {
            mockMvc.perform(post("/")).andExpect(status().isUnauthorized());
        }

        @Test
        @WithMockUser(authorities = "read:greetings")
        void whenHasReadScopeThenDeny() throws Exception {
            mockMvc.perform(post("/")).andExpect(status().isForbidden());
        }

        @Test
        @WithMockUser(authorities = "write:greetings")
        void whenHasWriteScopeThenGreet() throws Exception {
            mockMvc.perform(post("/")).andExpect(status().isOk());
        }

        @Test
        @WithMockUser(authorities = "randomagain")
        void whenHasWrongScopeThenDeny() throws Exception {
            mockMvc.perform(post("/")).andExpect(status().isForbidden());
        }
    }
}
