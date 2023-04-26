package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************************************************************************
 7.1.4.2.1. Subject Alternative Name Extension
 Certificate Field: extensions:subjectAltName
 Required/Optional:  Required
 Contents:  This extension MUST contain at least one entry.  Each entry MUST be either a dNSName containing
 the Fully‐Qualified Domain Name or an iPAddress containing the IP address of a server.  The CA MUST
 confirm that the Applicant controls the Fully‐Qualified Domain Name or IP address or has been granted the
 right to use it by the Domain Name Registrant or IP address assignee, as appropriate.
 Wildcard FQDNs are permitted.
 *************************************************************************************************************/

@Lint(
        name = "e_ext_san_directory_name_present",
        description = "The Subject Alternate Name extension MUST contain only 'dnsName' and 'ipaddress' name types",
        citation = "BRs: 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class ExtSanDirectoryNamePresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return ExtSanDirectoryNamePresent.sanContainsGeneralNameWithTag(certificate, 4);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }

    protected static LintResult sanContainsGeneralNameWithTag(X509Certificate certificate, int tagNumber) {
        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        try {
            List<GeneralName> allGeneralNames = Utils.getAllGeneralNames(rawSAN);
            boolean prohibitedFound = allGeneralNames.stream().anyMatch(generalName -> generalName.getTagNo() == tagNumber);

            if (prohibitedFound) {
                return LintResult.of(Status.ERROR);
            }
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }
}
