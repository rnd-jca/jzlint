package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/**
 * f. extKeyUsage (SHALL be present)
 * Generation KeyPurposeId
 * Strict id-kp-emailProtection SHALL be present. Other values SHALL NOT be present.
 * Multipurpose and
 * Legacy
 * id-kp-emailProtection SHALL be present. Other values MAY be present
 */
@Lint(
        name = "e_smime_eku_mail_protection_missing",
        description = "Check if the certificate has the id-kp-emailProtection extended key usage",
        citation = "SMIME BR 7.1.2.3f",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SMimeEkuMailProtectionMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection)) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && Utils.hasExtendedKeyUsageExtension(certificate);
    }

}