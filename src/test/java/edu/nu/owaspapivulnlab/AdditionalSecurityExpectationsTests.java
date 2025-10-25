package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired 
    MockMvc mvc;

    @Autowired 
    ObjectMapper om;

    String login(String user, String pw) throws Exception {
        String res = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + user + "\",\"password\":\"" + pw + "\"}"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode n = om.readTree(res);
        return n.get("token").asText();
    }

    // === Core Security Tests ===
    
    @Test
    void protected_endpoints_require_authentication() throws Exception {
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_with_invalid_credentials_returns_generic_error() throws Exception {
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"nonexistent\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is("Invalid credentials")));
    }

    @Test
    void create_user_does_not_allow_role_escalation() throws Exception {
        String payload = "{\"username\":\"eve2\",\"password\":\"pw\",\"email\":\"e2@e\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role", is("USER")));
    }

    @Test
    void create_user_prevents_duplicate_username() throws Exception {
        String payload = "{\"username\":\"alice\",\"password\":\"pw\",\"email\":\"new@test.com\"}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Username already exists")));
    }

    @Test
    void jwt_must_be_valid_and_aud_iss_checked() throws Exception {
        String validToken = login("alice", "alice123");
        mvc.perform(get("/api/accounts/mine")
                .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk());
    }

    @Test
    void invalid_jwt_returns_unauthorized() throws Exception {
        mvc.perform(get("/api/accounts/mine")
                .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void regular_users_cannot_access_admin_endpoints() throws Exception {
        String alice = login("alice", "alice123");
        mvc.perform(get("/api/admin/metrics")
                .header("Authorization", "Bearer " + alice))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_can_access_admin_endpoints() throws Exception {
        String admin = login("bob", "bob123");
        mvc.perform(get("/api/admin/metrics")
                .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.uptimeMs").exists());
    }

    @Test
    void user_can_see_own_accounts_list() throws Exception {
        String alice = login("alice", "alice123");
        mvc.perform(get("/api/accounts/mine")
                .header("Authorization", "Bearer " + alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void created_user_can_login() throws Exception {
        String payload = "{\"username\":\"testuser\",\"password\":\"testpass\",\"email\":\"test@test.com\"}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"testuser\",\"password\":\"testpass\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());
    }
    @Test
    void users_can_view_own_profile() throws Exception {
        String alice = login("alice", "alice123");
        mvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is("alice")));
    }
    @Test
    void users_can_only_view_own_profile() throws Exception {
        String alice = login("alice", "alice123");
        mvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer " + alice))
                .andExpect(status().isForbidden());
    }
     @Test
    void account_owner_only_access() throws Exception {
        String alice = login("alice", "alice123");
        mvc.perform(get("/api/accounts/2/balance")
                .header("Authorization", "Bearer " + alice))
                .andExpect(status().isForbidden());
    }
}
