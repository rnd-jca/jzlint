package de.mtg.jzlint.lints.cabf_smime_br;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.Status;

class AuthorityKeyIdentifierCorrectTest {

    @LintTest(
            name = "e_authority_key_identifier_correct",
            filename = "smime/authority_key_identifier_valid.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert has keyIdentifier")
    void testCase01() {
    }

    @LintTest(
            name = "e_authority_key_identifier_correct",
            filename = "smime/authority_key_identifier_invalid.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - cert has serial and DirName")
    void testCase02() {
    }

}
