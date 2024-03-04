package de.mtg.jzlint.lints.cabf_smime_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_single_email_if_present",
        description = "If present, the subject:emailAddress SHALL contain a single Mailbox Address",
        citation = "7.1.4.2.h",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SingleEmailIfPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> emails = Utils.getEmails(certificate);

            for (String email : emails) {
                if (!SMIMEUtils.isValidEmailAddress(email)) {
                    return LintResult.of(Status.ERROR, String.format("subject:emailAddress was present and contained an invalid email address (%s)", email));
                }
            }
            return LintResult.of(Status.PASS);
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }


    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) &&
                    Utils.getEmails(certificate).size() > 0 &&
                    SMIMEUtils.isSMIMEBRCertificate(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
