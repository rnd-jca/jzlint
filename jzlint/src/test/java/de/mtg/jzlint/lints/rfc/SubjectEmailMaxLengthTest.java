package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectEmailMaxLengthTest {

    @LintTest(
            name = "e_subject_email_max_length",
            filename = "subjectEmailPresent.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_email_max_length",
            filename = "SubjectEmailToolLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}