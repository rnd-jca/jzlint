package de.mtg.jzlint.lints.cabf_smime_br;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(LintTestExtension.class)
class RegistrationSchemeIdMatchesSubjectCountryTest {

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validated_with_matching_country.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - organization validated certificate with subject:Name:Country matching subject:organizationIdentifier")
    void testCase01() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/sponsor_validated_with_matching_country.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - sponsor validated certificate with subject:Name:Country matching subject:organizationIdentifier")
    void testCase02() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/individual_validated_with_matching_country.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "error - individual validated certificate")
    void testCase03() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validatged_with_no_country_specified.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "error - no country specified in certificate")
    void testCase04() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validated_with_incorrect_format_identifier.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "error - organization validated certificate with subject:organizationIdentifier in incorrect format")
    void testCase05() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validated_with_non_matching_country.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - organization validated certificate with subject:Name:Country not matching subject:organizationIdentifier")
    void testCase06() {
    }

}