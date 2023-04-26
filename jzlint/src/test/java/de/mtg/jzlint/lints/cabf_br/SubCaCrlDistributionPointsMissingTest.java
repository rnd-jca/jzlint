package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaCrlDistributionPointsMissingTest {

    @LintTest(
            name = "e_sub_ca_crl_distribution_points_missing",
            filename = "subCAWNocrlDist.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_ca_crl_distribution_points_missing",
            filename = "subCAWcrlDistNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
