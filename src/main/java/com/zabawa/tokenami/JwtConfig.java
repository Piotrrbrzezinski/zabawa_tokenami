package com.zabawa.tokenami;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.UUID;

@Configuration
public class JwtConfig {

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static String toPemFormat(PublicKey publicKey) {
        // Pobierz zakodowany klucz publiczny
        byte[] encoded = publicKey.getEncoded();
        // Koduj klucz jako tekst w formacie Base64
        String base64Encoded = Base64.getEncoder().encodeToString(encoded);
        // Buduj string PEM
        return "-----BEGIN PUBLIC KEY-----\n" + base64Encoded + "\n-----END PUBLIC KEY-----";
    }


   @Bean
   JwtEncoder jwtEncoder() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, JOSEException {

       var jwk = generateRsaKey();

       PublicKey publicKey = jwk.toRSAPublicKey();

       // Konwersja na format PEM
       String pemPublicKey = toPemFormat(publicKey);

       // Wydrukuj klucz publiczny w formacie PEM
       System.out.println(pemPublicKey);
       var jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
       return new NimbusJwtEncoder(jwks);
   }

}







