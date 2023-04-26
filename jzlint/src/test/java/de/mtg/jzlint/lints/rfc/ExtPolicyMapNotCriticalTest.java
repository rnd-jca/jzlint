package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtPolicyMapNotCriticalTest {

    @LintTest(
            name = "w_ext_policy_map_not_critical",
            filename = "policyMapNotCritical.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_policy_map_not_critical",
            filename = "policyMapGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}