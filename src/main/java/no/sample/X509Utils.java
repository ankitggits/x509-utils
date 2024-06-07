package no.sample;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class X509Utils {

    private static final CertificateFactory CERTIFICATE_FACTORY;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern CRL_PATTERN = Pattern.compile("BEGIN X509 CRL-+\r?\n?(.*[^-])\r?\n?-+END X509 CRL", Pattern.DOTALL);
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
    private static final String END_CERT = "\n-----END CERTIFICATE-----\n";
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    static {
        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (final CertificateException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public static boolean verifyPayload(SampleRequest request, X509Certificate extractedCert) {
        String dn = extractedCert.getSubjectDN().getName();
        Map<String, String> rdns = new HashMap<>();
        String[] parts = dn.split(",");
        for (String part : parts) {
            String[] rdn = part.split("=");
            rdns.put(rdn[0].trim(), rdn[1].trim());
        }
        if(!(rdns.containsKey("CN") && rdns.containsKey("DC"))) {
            return false;
        }
        return rdns.get("CN").equalsIgnoreCase(request.application())
                && rdns.get("DC").equalsIgnoreCase(request.environment());
    }

    public static SampleRequest parseRequest(String base64EncodedBody) throws GeneralSecurityException {
        try {
            return OBJECT_MAPPER.readValue(Base64.getUrlDecoder().decode(base64EncodedBody), SampleRequest.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new GeneralSecurityException("unable to parse deployment request", e);
        }
    }

    public static <T> T notNull(final T argument, final String name) {
        if (argument == null) {
            throw new IllegalArgumentException(name + " may not be null");
        }
        return argument;
    }

    public static X509CRL getCRLFromPEM(String pemContent) throws GeneralSecurityException {
        notNull("pemContent", pemContent);
        final Matcher m = CRL_PATTERN.matcher(pemContent);
        final byte[] certBytes;
        if (m.find()) {
            certBytes = pemContent.getBytes();
        } else {
            certBytes = ("-----BEGIN X509 CRL-----\n" + pemContent + "\n-----END X509 CRL-----").getBytes();
        }
        final CRL cert = CERTIFICATE_FACTORY.generateCRL(new ByteArrayInputStream(certBytes));
        if ("X.509".equals(cert.getType()))
            return (X509CRL) cert;
        throw new GeneralSecurityException("PEM-encoded CRL is not X.509 but [" + cert.getType() + "]");
    }

    public static boolean verifyRSA(X509Certificate extractedCert, X509Certificate caCert) {
        if (!extractedCert.getIssuerDN().equals(caCert.getSubjectDN())) {
            return false;
        }
        try {
            extractedCert.verify(caCert.getPublicKey());
            return true;
        } catch (GeneralSecurityException verifyFailed) {
            return false;
        }
    }

    public static boolean verifyCRL(X509Certificate extractedCert, String crlContent) {
        try {
            X509CRL crl = getCRLFromPEM(crlContent);
            return !crl.isRevoked(extractedCert);
        } catch (GeneralSecurityException verifyFailed) {
            return false;
        }
    }

    public static String extractX5c(String base64EncodedHeader) throws GeneralSecurityException {
        try {
            JsonNode jsonNode = OBJECT_MAPPER.readTree(org.apache.commons.codec.binary.Base64.decodeBase64(base64EncodedHeader));
            JsonNode x5c = jsonNode.get("x5c").get(0);
            return beautify(x5c.asText());
        } catch (IOException e) {
            e.printStackTrace();
            throw new GeneralSecurityException("no x5c token found");
        }
    }

    public static X509Certificate getX509Certificate(String certString) throws CertificateException {
        byte[] certBytes = certString.getBytes(StandardCharsets.UTF_8);
        InputStream in = new ByteArrayInputStream(certBytes);
        return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(in);
    }

    public static String beautify(String cert) {
        return beautify(BaseEncoding.base64()
                .withSeparator(LINE_SEPARATOR, 64)
                .encode(Base64.getDecoder().decode(cert)), BEGIN_CERT, END_CERT);
    }

    public static String beautify(String cert, String beginText, String endText) {
        StringWriter sw = new StringWriter();
        sw.write(beginText);
        sw.write(cert);
        sw.write(endText);
        return sw.toString();
    }
}
