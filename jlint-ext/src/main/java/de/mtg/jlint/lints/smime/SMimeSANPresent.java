package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/**
 * 7.1.2.3 Subscriber certificates
 * h. subjectAlternativeName (SHALL be present)
 * This extension SHOULD NOT be marked critical unless the subject field is an empty
 * sequence.
 * The value of this extension SHALL be encoded as specified in Section 7.1.4.2.1.
 */
@Lint(
        name = "e_smime_san_present",
        description = "Check if the certificate has the subject alternative name extension.",
        citation = "SMIME BR 7.1.2.3h",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SMimeSANPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}