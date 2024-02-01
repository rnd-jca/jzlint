package de.mtg.jzlint.lints.cabf_br;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(LintTestExtension.class)
class SubCertAiaContainsInternalNamesTest {

    @LintTest(
            name = "w_sub_cert_aia_contains_internal_names",
            filename = "aiaWithValidNames.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - aia with valid names")
    void testCase01() {
    }

    @LintTest(
            name = "w_sub_cert_aia_contains_internal_names",
            filename = "aiaWithInternalNames.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "warn - aia with internal names")
    void testCase02() {
    }

}
