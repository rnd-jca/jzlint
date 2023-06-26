package de.mtg.jlint.lints.rfc;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.security.cert.X509Certificate;

class IssuerPostalCodeMaxLengthTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createNACertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.NA), new IssuerPostalCodeMaxLength(), certificate);
    }

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createMaximumLengthCertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.PASS), new IssuerPostalCodeMaxLength(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createExceedingMaximumLengthCertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), new IssuerPostalCodeMaxLength(), certificate);
    }

}
