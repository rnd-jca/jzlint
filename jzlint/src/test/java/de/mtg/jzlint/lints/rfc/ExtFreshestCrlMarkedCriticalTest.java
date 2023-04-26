package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtFreshestCrlMarkedCriticalTest {

    @LintTest(
            name = "e_ext_freshest_crl_marked_critical",
            filename = "frshCRLCritical.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_freshest_crl_marked_critical",
            filename = "frshCRLNotCritical.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}