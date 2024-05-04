package com.zabawa.tokenami;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class JwtService {
    @Autowired
    private JwtEncoder jwtEncoder;

    public String generateToken(String username) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("ExampleIssuer")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600)) // Token ważny przez 1 godzinę
                .subject(username)
                .claim("role", "USER")
                .claim("ppp","qq1")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
