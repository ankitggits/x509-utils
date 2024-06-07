package no.sample;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.util.encoders.Base64;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static no.sample.X509Utils.*;


public class Main {

    private static final String HEADER = "header";
    private static final String PAYLOAD = "payload";
    public static final String JWT_REGEX = "^(?<" + HEADER + ">[a-zA-Z0-9_=]+)\\.(?<" + PAYLOAD + ">[a-zA-Z0-9_=]+)\\.(?<signature>[a-zA-Z0-9_\\-+/=]*)";
    private static final Pattern JWT_PATTERN = Pattern.compile(JWT_REGEX);

    public static void main(String[] args) {

        try {
            X509TestHelper.X509 root = X509TestHelper.generateRootCACertificate();
            String pem = X509TestHelper.convertToPem(root.getCert());
            X509Certificate caCert = getX509Certificate(pem);

            String revokedCRL = X509TestHelper.generateCrl(root, null);

            X509TestHelper.X509 x509 = X509TestHelper.generateApplicationCertificate(root, "sample-application", "test");

            String signedJwt = createJwtSignedRequest(x509.getKeyPair().getPrivate(), new String(Base64.encode(x509.getCert().getEncoded())), new SampleRequest("sample-application", "test"));

            Matcher matcher = validateJwt(new SampleSecuredRequest(signedJwt));
            X509Certificate extractedCert = getX509Certificate(extractX5c(matcher.group(HEADER)));

            boolean rsaVerified = verifyRSA(extractedCert, caCert);
            boolean crlVerified = verifyCRL(extractedCert, revokedCRL);

            SampleRequest request = parseRequest(matcher.group(PAYLOAD));

            System.out.println(STR."application \{request.application()} and environment \{request.environment()} verified: \{rsaVerified && crlVerified}");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Matcher validateJwt(SampleSecuredRequest request) {
        if(request == null || request.payload() == null) {
            throw new IllegalArgumentException("request must be provided");
        }
        Matcher matcher = JWT_PATTERN.matcher(request.payload());
        if(!matcher.matches()) {
            throw new IllegalArgumentException("request is invalid");
        }
        return matcher;
    }

    private static String createJwtSignedRequest(PrivateKey privateKey, String publicKey, SampleRequest request) {
        ObjectMapper objectMapper = new ObjectMapper();
        return Jwts.builder()
                .addClaims(objectMapper.convertValue(request, Map.class))
                .setHeaderParam("x5c", new String[]{publicKey})
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }




}

