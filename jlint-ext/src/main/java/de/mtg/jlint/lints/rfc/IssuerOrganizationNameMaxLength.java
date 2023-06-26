package de.mtg.jlint.lints.rfc;

import de.mtg.jzlint.*;
import de.mtg.jzlint.utils.Utils;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import java.security.cert.X509Certificate;

/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-organization-name INTEGER ::= 64
 ************************************************/

@Lint(
        name = "e_issuer_organization_name_max_length",
        description = "The 'Organization Name' field of the issuer MUST be less than 65 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerOrganizationNameMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return IssuerCommonNameMaxLength.isIssuerComponentGreaterThan(certificate, X509ObjectIdentifiers.organization.getId(), 64);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId()).isEmpty();
    }

}
