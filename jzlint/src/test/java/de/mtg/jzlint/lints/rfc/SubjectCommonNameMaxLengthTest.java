package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectCommonNameMaxLengthTest {

    @LintTest(
            name = "e_subject_common_name_max_length",
            filename = "subjectCommonNameLengthGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_common_name_max_length",
            filename = "subjectCommonNameLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}