package de.mtg.jzlint.utils;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

public final class SMIMEUtils {

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
            MAILBOX_VALIDATED_LEGACY,
            MAILBOX_VALIDATED_MULTIPURPOSE,
            MAILBOX_VALIDATED_STRICT
    );

    private static final List<String> LEGACY_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_LEGACY,
            ORGANIZATION_VALIDATED_LEGACY,
            SPONSOR_VALIDATED_LEGACY,
            INDIVIDUAL_VALIDATED_LEGACY
    );

    private static final List<String> MULTIPURPOSE_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_MULTIPURPOSE,
            ORGANIZATION_VALIDATED_MULTIPURPOSE,
            SPONSOR_VALIDATED_MULTIPURPOSE,
            INDIVIDUAL_VALIDATED_MULTIPURPOSE
    );

    private static final List<String> STRICT_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_STRICT,
            ORGANIZATION_VALIDATED_STRICT,
            SPONSOR_VALIDATED_STRICT,
            INDIVIDUAL_VALIDATED_STRICT
    );

    private static final List<String> ORGANIZATION_VALIDATED_OIDS = Arrays.asList(
            ORGANIZATION_VALIDATED_LEGACY,
            ORGANIZATION_VALIDATED_MULTIPURPOSE,
            ORGANIZATION_VALIDATED_STRICT,
            INDIVIDUAL_VALIDATED_STRICT
    );

    private static final List<String> SPONSOR_VALIDATED_OIDS = Arrays.asList(
            SPONSOR_VALIDATED_LEGACY,
            SPONSOR_VALIDATED_MULTIPURPOSE,
            SPONSOR_VALIDATED_STRICT
    );

    private static final Function<PolicyInformation, String> getOID = p -> p.getPolicyIdentifier().getId();

    private SMIMEUtils() {
        // empty
    }

    public static boolean isMailboxValidatedCertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

        Predicate<PolicyInformation> isMailboxValidatedPolicy = p -> MAILBOX_VALIDATED_OIDS.contains(getOID.apply(p));

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isMailboxValidatedPolicy);
    }

    public static boolean isLegacySMIMECertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

        Predicate<PolicyInformation> isLegacy = p -> LEGACY_OIDS.contains(getOID.apply(p));

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isLegacy);
    }

    public static boolean isMultipurposeSMIMECertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isMailboxValidatedPolicy = p -> MULTIPURPOSE_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isMailboxValidatedPolicy);

    }

    public static boolean isStrictSMIMECertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isStrictPolicy = p -> STRICT_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isStrictPolicy);

    }

    public static boolean isSMIMEBRCertificate(X509Certificate certificate) {
        return isLegacySMIMECertificate(certificate) ||
                isMultipurposeSMIMECertificate(certificate) ||
                isStrictSMIMECertificate(certificate);
    }

    public static boolean isOrganizationValidatedCertificate(X509Certificate certificate) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isOrganizationValidatedPolicy = p -> ORGANIZATION_VALIDATED_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isOrganizationValidatedPolicy);
    }

    public static boolean isSponsorValidatedCertificate(X509Certificate certificate) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isSponsorValidatedPolicy = p -> SPONSOR_VALIDATED_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isSponsorValidatedPolicy);
    }

}
