package spring.example.springjwtvalidierung.controller.rest;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@RestController
public class JwtController {

    @Value("${authentication.rsa-public-key}")
    public String publicKey;

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/echo-jwt",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> getEchoJwt(@RequestHeader(value = "Authorization") String jwt) {
        return new ResponseEntity("{\"jwt\": \"" + jwt + "\"}", HttpStatus.OK);
    }

    @RequestMapping(
            method = RequestMethod.POST,
            value = "/echo-signature",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> postSignatureState(@RequestHeader(value = "Authorization") String jwt) {

        final String cleanJwt = jwt.replaceFirst("(?i)(^bearer\\s+)", "");

        final JwtTokenPayload jwtTokenPayload = parseTokenPayload(cleanJwt);
        final String clientId = jwtTokenPayload.getClientId();
        final List<String> roles = jwtTokenPayload.getRoles();
        final String haendlerId = jwtTokenPayload.getHaendlerId();

        return new ResponseEntity("{"
                + "  \"roles\": \"" + roles + "\","
                + "  \"haendlerId\": \"" + haendlerId + "\","
                + "  \"clientId\": \"" + clientId + "\""
                + "}",
                HttpStatus.OK);
    }

    // Parse

    boolean isRsaFamiliy(final String jwtToken) {

        final String[] split_string = jwtToken.split("\\.");
        final String base64EncodedHeader = split_string[0];

        final Base64.Decoder decoder = Base64.getDecoder();
        // CHECKSTYLE:OFF
        final String header = new String(decoder.decode(base64EncodedHeader), StandardCharsets.UTF_8);
        // CHECKSTYLE:ON
        final JsonParser jsonParser = new JsonParser();
        final JsonElement jsonHeader = jsonParser.parse(header);
        final String algorithmFamily = jsonHeader.getAsJsonObject().get("alg").getAsString();

        return algorithmFamily != null && algorithmFamily.startsWith("RS");
    }

    public JwtTokenPayload parseTokenPayload(final String token) throws RuntimeException {
        final Claims claims = extractClaimsFromToken(token);
        return new JwtTokenPayload(claims);
    }

    Claims extractClaimsFromToken(final String token) {
        Claims claims = null;

        try {
            if (token != null && isRsaFamiliy(token)) {
                claims = Jwts.parser().setSigningKey(parsePublicKey(publicKey)).parseClaimsJws(token).getBody();
            } else {
                throw new RuntimeException(
                        String.format(
                                "Unterstuetz sind nur nicht leere JWT-Tokens mit einer RSA-Signature. Token = %s",
                                token));
            }
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        }
        return claims;
    }

    PublicKey parsePublicKey(final String publicKeyString) {
        final KeyFactory kf;
        PublicKey publicKey = null;
        try {

            kf = KeyFactory.getInstance("RSA");
            final X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            publicKey = kf.generatePublic(spec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return publicKey;
    }
}
