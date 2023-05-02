package de.mtg.jlintissuer;

import de.mtg.jzlint.LintResult;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public interface JavaCRLIssuerLint {

    LintResult execute(X509CRL crl, X509Certificate issuerCertificate);

    boolean checkApplies(X509CRL crl, X509Certificate issuerCertificate);

}
