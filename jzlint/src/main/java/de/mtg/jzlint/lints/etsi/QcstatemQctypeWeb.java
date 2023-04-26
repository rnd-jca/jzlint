package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "w_qcstatem_qctype_web",
        description = "Checks that a QC Statement of the type Id-etsi-qcs-QcType features at least the type IdEtsiQcsQctWeb",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.2.3",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemQctypeWeb implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Encodable statementInfo = QcUtils.getStatementInfo(certificate, QcUtils.id_etsi_qcs_QcType);

        if (!(statementInfo instanceof ASN1Sequence)) {
            return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcType value");
        }

        StringBuilder errorStringBuilder = new StringBuilder();
        StringBuilder warnStringBuilder = new StringBuilder();

        ASN1Sequence qcType = (ASN1Sequence) statementInfo;

        if (qcType.size() == 0) {
            errorStringBuilder.append("no QcType present, sequence of OIDs is empty");
            errorStringBuilder.append(";");
        }

        boolean found = false;

        Iterator<ASN1Encodable> iterator = qcType.iterator();
        while (iterator.hasNext()) {
            ASN1Encodable encodeable = iterator.next();

            if (!(encodeable instanceof ASN1ObjectIdentifier)) {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcType value");
            }

            ASN1ObjectIdentifier oid = ((ASN1ObjectIdentifier) encodeable);

            if (oid.equals(QcUtils.id_etsi_qcs_web)) {
                found = true;
            }
        }

        if (!found) {
            warnStringBuilder.append("etsi Type does not indicate certificate as a 'web' certificate");
            warnStringBuilder.append(";");
        }

        if (!errorStringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.ERROR, errorStringBuilder.toString());
        }

        if (!warnStringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.WARN, warnStringBuilder.toString());
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcType);
    }

}
