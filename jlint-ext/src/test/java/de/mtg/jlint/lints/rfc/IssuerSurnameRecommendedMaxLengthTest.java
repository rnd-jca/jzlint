package de.mtg.jlint.lints.rfc;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.security.cert.X509Certificate;

class IssuerSurnameRecommendedMaxLengthTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createNACertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.NA), new IssuerSurnameRecommendedMaxLength(), certificate);
    }

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createMaximumLengthCertificate(caExtension, 2, 2, 2, 2, 2, 2, 64, 2, 2, 2, 2, false);
        caExtension.assertLintResult(LintResult.of(Status.PASS), new IssuerSurnameRecommendedMaxLength(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createMaximumLengthCertificate(caExtension, 2, 2, 2, 2, 2, 2, 65, 2, 2, 2, 2, false);
        caExtension.assertLintResult(LintResult.of(Status.WARN), new IssuerSurnameRecommendedMaxLength(), certificate);
    }

}
