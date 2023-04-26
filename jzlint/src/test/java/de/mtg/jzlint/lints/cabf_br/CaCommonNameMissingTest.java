package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CaCommonNameMissingTest {

    @LintTest(
            name = "e_ca_common_name_missing",
            filename = "caCommonNameMissing.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ca_common_name_missing",
            filename = "caCommonNameNotMissing.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}