package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/***********************************************************************
 RFC 5280: 4.2.1.1
 The keyIdentifier field of the authorityKeyIdentifier extension MUST
 be included in all certificates generated by conforming CAs to
 facilitate certification path construction.  There is one exception;
 where a CA distributes its public key in the form of a "self-signed"
 certificate, the authority key identifier MAY be omitted.  The
 signature on a self-signed certificate is generated with the private
 key associated with the certificate's subject public key.  (This
 proves that the issuer possesses both the public and private keys.)
 In this case, the subject and authority key identifiers would be
 identical, but only the subject key identifier is needed for
 certification path building.
 ***********************************************************************/
@Lint(
        name = "e_ext_authority_key_identifier_no_key_identifier",
        description = "CAs must include keyIdentifier field of AKI in all non-self-issued certificates",
        citation = "RFC 5280: 4.2.1.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtAuthorityKeyIdentifierNoKeyIdentifier implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isSelfSigned(certificate) && Utils.isCA(certificate)) {
            return LintResult.of(Status.PASS);
        }

        if (!Utils.hasAuthorityKeyIdentifierExtension(certificate)) {
            return LintResult.of(Status.ERROR);
        }

        byte[] rawAKI = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (rawAKI == null) {
            return LintResult.of(Status.ERROR);
        }

        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(rawAKI).getOctets());
        if (authorityKeyIdentifier.getKeyIdentifier() == null) {
            return LintResult.of(Status.ERROR);
        } else {
            return LintResult.of(Status.PASS);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
