package no.sample;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;

public class X509TestHelper {

    private static final X500Name rootCertName = new X500Name("CN=root-cert");
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static KeyPairGenerator keyPairGenerator;

    protected static X509 generateRootCACertificate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertName, rootSerialNum, startDate(), endDate(), rootCertName, rootKeyPair.getPublic());
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);
        return new X509().rootSerialNum(rootSerialNum).cert(rootCert).keyPair(rootKeyPair);
    }

    protected static String generateCrl(X509 root, BigInteger serialNumber) throws Exception {
        X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(root.cert.getIssuerX500Principal(), startDate());
        if(serialNumber != null) builder.addCRLEntry(serialNumber, startDate(), CRLReason.cACompromise);
        builder.setNextUpdate(endDate());
        builder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(root.cert));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(new BigInteger("4096")));
        X509CRLHolder cRLHolder = builder.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(root.keyPair.getPrivate()));
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new MiscPEMGenerator(cRLHolder));
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    protected static X509 generateApplicationCertificate(X509 root, String app, String env) throws Exception{
        X500Name issuedCertSubject = new X500Name(String.format("CN=%s, DC=%s", app, env));
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        ContentSigner csrContentSigner = csrBuilder.build(root.keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertName, issuedCertSerialNum, startDate(), endDate(), csr.getSubject(), csr.getSubjectPublicKeyInfo());
        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(root.cert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
        return new X509().rootSerialNum(issuedCertSerialNum).cert(certificate).keyPair(issuedCertKeyPair);
    }

    protected static String convertToPem(X509Certificate cert) throws CertificateEncodingException {
        org.apache.commons.codec.binary.Base64 encoder = new org.apache.commons.codec.binary.Base64(64);
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";

        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;
        return pemCert;
    }

    static void print(Logger log, X509Certificate certificate, String name) {
        log.info("------------" + name + "------------");
        log.info("Subject DN : " + certificate.getSubjectDN().getName());
        log.info("Issuer : " + certificate.getIssuerDN().getName());
        log.info("Not After: " + certificate.getNotAfter());
        log.info("Not Before: " + certificate.getNotBefore());
        log.info("version: " + certificate.getVersion());
        log.info("serial number : " + certificate.getSerialNumber());
        log.info("--------------------------------");
    }

    private static Date startDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        return calendar.getTime();
    }

    private static Date endDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, 1);
        return calendar.getTime();
    }

    protected static class X509 {
        BigInteger serialNumber;
        X509Certificate cert;
        KeyPair keyPair;

        X509 cert(X509Certificate cert) {
            this.cert = cert;
            return this;
        }

        X509 rootSerialNum(BigInteger rootSerialNum) {
            this.serialNumber = rootSerialNum;
            return this;
        }

        X509 keyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
            return this;
        }

        public BigInteger getSerialNumber() {
            return serialNumber;
        }

        public KeyPair getKeyPair() {
            return keyPair;
        }

        public X509Certificate getCert() {
            return cert;
        }
    }
}