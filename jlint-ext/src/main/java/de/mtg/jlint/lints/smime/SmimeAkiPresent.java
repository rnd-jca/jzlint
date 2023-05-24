package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/**
 * 7.1.2.3 Subscriber certificates
 * g. authorityKeyIdentifier (SHALL be present)
 * This extension SHALL NOT be marked critical. The keyIdentifier field SHALL be
 * present. authorityCertIssuer and authorityCertSerialNumber fields SHALL NOT
 * be present.
 */
@Lint(
        name = "e_smime_authoritykeyidentifier_present",
        description = "Check if a subscriber certificate has the authority key identifier extension",
        citation = "SMIME BR 7.1.2.3g",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeAkiPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasAuthorityKeyIdentifierExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}