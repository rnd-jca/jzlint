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
 * b. cRLDistributionPoints (SHALL be present)
 * This extension SHOULD NOT be marked critical. It SHALL contain at least one
 * distributionPoint whose fullName value includes a GeneralName of type
 * uniformResourceIdentifier that includes a URI where the Issuing CA’s CRL can be
 * retrieved.
 */
@Lint(
        name = "e_smime_crldistributionpoints_present",
        description = "Check if a subscriber certificate has the cRLDistributionPoints extension",
        citation = "SMIME BR 7.1.2.3b",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCrlDistributionPointsPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasCRLDPExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}