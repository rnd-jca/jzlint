package de.mtg.jzlint.utils;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

public class SMIMEUtils {

    public static final String MAILBOX_VALIDATED_LEGACY = "2.23.140.1.5.1.1";
    public static final String MAILBOX_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.1.2";
    public static final String MAILBOX_VALIDATED_STRICT = "2.23.140.1.5.1.3";
    public static final String ORGANIZATION_VALIDATED_LEGACY = "2.23.140.1.5.2.1";
    public static final String ORGANIZATION_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.2.2";
    public static final String ORGANIZATION_VALIDATED_STRICT = "2.23.140.1.5.2.3";
    public static final String SPONSOR_VALIDATED_LEGACY = "2.23.140.1.5.3.1";
    public static final String SPONSOR_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.3.2";
    public static final String SPONSOR_VALIDATED_STRICT = "2.23.140.1.5.3.3";
    public static final String INDIVIDUAL_VALIDATED_LEGACY = "2.23.140.1.5.4.1";
    public static final String INDIVIDUAL_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.4.2";
    public static final String INDIVIDUAL_VALIDATED_STRICT = "2.23.140.1.5.4.3";

    private static final List<String> MAILBOX_VALIDATED_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_LEGACY, MAILBOX_VALIDATED_MULTIPURPOSE, MAILBOX_VALIDATED_STRICT
    );

    private SMIMEUtils() {
        // empty
    }

    public static boolean isMailboxValidatedCertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());

        Predicate<PolicyInformation> isMailboxValidatedPolicy = p -> MAILBOX_VALIDATED_OIDS.contains(p.getPolicyIdentifier().getId());

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isMailboxValidatedPolicy);
    }

}
