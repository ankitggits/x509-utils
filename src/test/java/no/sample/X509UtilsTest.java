package no.sample;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;

import static no.sample.X509TestHelper.*;
import static no.sample.X509Utils.*;
import static org.junit.jupiter.api.Assertions.*;

class X509UtilsTest {

    public static final String ENV_UNDER_TEST = "junit";
    private static final String APP_UNDER_TEST = "junit-test-app";

    private static X509TestHelper.X509 root;
    private static X509TestHelper.X509 chain;

    @BeforeAll
    static void setup() throws Exception {
        root = generateRootCACertificate();
        chain = generateApplicationCertificate(root, APP_UNDER_TEST, ENV_UNDER_TEST);
    }

    @Test
    void verify_public_key() throws CertificateEncodingException {
        String publicKey = new String(Base64.encode(chain.cert.getEncoded()));
        assertNotNull(X509Utils.beautify(publicKey));
    }

    @Test
    void verify_rsa() {
        assertTrue(verifyRSA(chain.cert, root.cert));
    }

    @Test
    void verify_wrong_root_rsa() throws Exception {
        X509TestHelper.X509 anotherChain = generateApplicationCertificate(generateRootCACertificate(), APP_UNDER_TEST, ENV_UNDER_TEST);
        assertFalse(verifyRSA(anotherChain.cert, root.cert));
    }

    @Test
    void verify_revoked_serial() throws Exception {
        BigInteger revokeThisSerial = BigInteger.valueOf(new SecureRandom().nextLong());
        String crlContent = generateCrl(root, revokeThisSerial);
        assertTrue(verifyCRL(chain.cert, crlContent));
        X509CRL crlFromPEM = getCRLFromPEM(crlContent);
        assertEquals(1, crlFromPEM.getRevokedCertificates().size());
        assertNotNull(crlFromPEM.getRevokedCertificate(revokeThisSerial));
        assertEquals(revokeThisSerial, crlFromPEM.getRevokedCertificate(revokeThisSerial).getSerialNumber());
    }

    @Test
    void verify_chain_revoked_serial() throws Exception {
        String crlContent = generateCrl(root, chain.cert.getSerialNumber());
        assertFalse(verifyCRL(chain.cert, crlContent));
    }

    @Test
    void verify_payload() {
        SampleRequest request = new SampleRequest(APP_UNDER_TEST, ENV_UNDER_TEST);
        assertTrue(verifyPayload(request, chain.cert));
    }

    @Test
    void verify_wrong_application_payload() {
        SampleRequest request = new SampleRequest(APP_UNDER_TEST + "SOMETHING", ENV_UNDER_TEST);
        assertFalse(verifyPayload(request, chain.cert));
    }

    @Test
    void verify_wrong_env_payload() {
        SampleRequest request = new SampleRequest(APP_UNDER_TEST, ENV_UNDER_TEST + "SOMETHING");
        assertFalse(verifyPayload(request, chain.cert));
    }

}