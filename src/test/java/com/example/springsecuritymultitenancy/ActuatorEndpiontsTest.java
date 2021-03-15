package com.example.springsecuritymultitenancy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ActuatorEndpiontsTest {
    @Autowired private MockMvc mockMvc;

    @Nested
    class HealthEndpoint {
        @Test
        @WithAnonymousUser
        void allowAnonymous() throws Exception {
            mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        }

        @Test
        @WithMockUser
        void ifAuthenticatedThenDeny() throws Exception {
            mockMvc.perform(get("/actuator/health")).andExpect(status().isForbidden());
        }
    }

    @Nested
    class InfoEndpoint {
        @Test
        @WithAnonymousUser
        void denyAnonymous() throws Exception {
            mockMvc.perform(get("/actuator/info")).andExpect(status().isUnauthorized());
        }

        @Test
        @WithMockUser
        void allowAuthenticated() throws Exception {
            mockMvc.perform(get("/actuator/info")).andExpect(status().isOk());
        }
    }
}
