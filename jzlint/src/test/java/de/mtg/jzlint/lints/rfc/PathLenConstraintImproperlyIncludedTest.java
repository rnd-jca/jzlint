package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class PathLenConstraintImproperlyIncludedTest {

    @LintTest(
            name = "e_path_len_constraint_improperly_included",
            filename = "caMaxPathLenPresentNoCertSign.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_path_len_constraint_improperly_included",
            filename = "caMaxPathLenPositive.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_path_len_constraint_improperly_included",
            filename = "caMaxPathLenMissing.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_path_len_constraint_improperly_included",
            filename = "subCertPathLenPositive.pem",
            expectedResultStatus = Status.ERROR)
    void testCase04() {
    }

    @LintTest(
            name = "e_path_len_constraint_improperly_included",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }
}