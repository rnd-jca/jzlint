package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameEmptyLabelTest {

    @LintTest(
            name = "e_dnsname_empty_label",
            filename = "dnsNameEmptyLabel.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_dnsname_empty_label",
            filename = "dnsNameNotEmptyLabel.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}