package de.mtg.jzlint.lints.cabf_smime_br;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(LintTestExtension.class)
class SingleEmailIfPresentTest {

    @LintTest(
            name = "e_single_email_if_present",
            filename = "smime/single_email_present.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with one email address")
    void testCase01() {
    }

    @LintTest(
            name = "e_single_email_if_present",
            filename = "smime/no_email_present.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - cert with no email addresses")
    void testCase02() {
    }

    @LintTest(
            name = "e_single_email_if_present",
            filename = "smime/multiple_email_present.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - cert with multiple email addresses")
    void testCase03() {
    }

}