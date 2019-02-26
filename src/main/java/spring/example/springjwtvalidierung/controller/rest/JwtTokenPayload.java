package spring.example.springjwtvalidierung.controller.rest;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@AllArgsConstructor
class JwtTokenPayload {

    private final Claims claims;

    public String getPreferred_username() {
        return claims.get("preferred_username", String.class);
    }

    public List<String> getRoles() {
        final List<String> result = claims.get("roles", List.class);
        return (result != null) ? result : new ArrayList<>();
    }

    public String getHaendlerId() {
        return String.valueOf(claims.get("profile", HashMap.class).get("haendlerId"));
    }

    public String getSubject() {
        return claims.getSubject();
    }

    public String getClientId() {
        return claims.get("clientId", String.class);
    }
}
