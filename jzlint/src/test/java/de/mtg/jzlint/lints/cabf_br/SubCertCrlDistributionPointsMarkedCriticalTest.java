package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertCrlDistributionPointsMarkedCriticalTest {

    @LintTest(
            name = "e_sub_cert_crl_distribution_points_marked_critical",
            filename = "subCrlDistCrit.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_crl_distribution_points_marked_critical",
            filename = "subCrlDistNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}