/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r4.sca.model.signature;

import eu.europa.ec.eudi.signer.r4.sca.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.signer.r4.sca.model.QTSPClient;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signHash.SignHashRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signHash.SignHashResponse;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
public class SignatureService {

    private static final Logger fileLogger = LoggerFactory.getLogger("FileLogger");
    private final QTSPClient qtspClient;
    private final DSSService dssClient;
    private final TimestampAuthorityConfig timestampAuthorityConfig;

    public SignatureService(@Autowired QTSPClient qtspClient, @Autowired DSSService dssClient, @Autowired TimestampAuthorityConfig timestampAuthorityConfig) {
        this.qtspClient = qtspClient;
        this.dssClient = dssClient;
        this.timestampAuthorityConfig = timestampAuthorityConfig;
    }

    public List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate certificate,
                                           List<X509Certificate> certificateChain, CommonTrustedCertificateSource certificateSource,
                                           String hashAlgorithmOID, Date date) throws Exception {

        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            fileLogger.info("Payload Received:{Conformance Level:{}, Signature Format:{}, Hash Algorithm OID:{}, Signature Packaging:{}, Type of Container:{}}", document.getConformance_level(), document.getSignature_format(), hashAlgorithmOID, document.getSigned_envelope_property(), document.getContainer());

            if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                for (X509Certificate cert : certificateChain) {
                    certificateSource.addCertificate(new CertificateToken(cert));
                }
            }

			SignatureDocumentForm signatureDocumentForm = getSignatureForm(document, hashAlgorithmOID, certificate, date, certificateSource, certificateChain);

			byte[] dataToBeSigned = dssClient.getDigestOfDataToBeSigned(signatureDocumentForm);
            if (dataToBeSigned == null) continue;

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            String dataToBeSignedURLEncoded = URLEncoder.encode(dataToBeSignedStringEncoded, StandardCharsets.UTF_8);
            hashes.add(dataToBeSignedURLEncoded);
        }

        fileLogger.info("DataToBeSigned successfully created");
        return hashes;
    }

    public List<String> handleDocumentsSignDocRequest(
          String resourceServerUrl, String authorizationHeader, List<DocumentsSignDocRequest> documents, List<String> hashes,
          String credentialID, X509Certificate certificate, List<X509Certificate> certificateChain,
          CommonTrustedCertificateSource certificateSource, String signAlgo, String hashAlgorithmOID, Date date) throws Exception {

        SignHashRequest signHashRequest = new SignHashRequest();
        signHashRequest.setCredentialID(credentialID);
        signHashRequest.setSAD(null);
        signHashRequest.setHashes(hashes);
        signHashRequest.setHashAlgorithmOID(hashAlgorithmOID);
        signHashRequest.setSignAlgo(signAlgo);
        signHashRequest.setSignAlgoParams(null);
        signHashRequest.setOperationMode("S");
        signHashRequest.setValidity_period(-1);
        signHashRequest.setResponse_uri(null);

        SignHashResponse signHashResponse = qtspClient.requestSignHash(resourceServerUrl, authorizationHeader, signHashRequest);
        List<String> signatureObjects = signHashResponse.getSignatures();

        if (signatureObjects.size() != documents.size()) {
            fileLogger.error("The number of signature received doesn't match the number of documents to be signed.");
            throw new Exception("The number of signature received doesn't match the number of documents to be signed.");
        }

        List<String> signedDocuments = new ArrayList<>();
        for (int i = 0; i < documents.size(); i++) {
            DocumentsSignDocRequest document = documents.get(i);
            String signatureValue = signatureObjects.get(i);

            if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
                for (X509Certificate cert : certificateChain) {
                    certificateSource.addCertificate(new CertificateToken(cert));
                }
            }

            SignatureDocumentForm signatureDocumentForm = getSignatureForm(document, hashAlgorithmOID, certificate, date, certificateSource, certificateChain);
            signatureDocumentForm.setSignatureValue(Base64.getDecoder().decode(signatureValue));

            DSSDocument docSigned = dssClient.signDocument(signatureDocumentForm);
			fileLogger.info("Document successfully signed. Filename: {}. File MimeType: {}", docSigned.getName(), docSigned.getMimeType().getMimeTypeString());
            String signedDocumentString = getSignedDocumentString(document, docSigned);
            signedDocuments.add(signedDocumentString);
        }

        return signedDocuments;
    }

    public void validateSignatureRequest(List<DocumentsSignDocRequest> documents, String hashAlgorithmOID) throws Exception{
        if(hashAlgorithmOID == null){
            fileLogger.error("The digest/hash algorithm OID parameter is missing.");
            throw new Exception("The hashAlgorithmOID is missing.");
        }
        // validate if the hashAlgorithmOID is supported by the TSA
        if(!this.timestampAuthorityConfig.getSupportedDigestAlgorithm().contains(hashAlgorithmOID)){
            fileLogger.error("The hashAlgorithmOID chosen is not supported by the TSA.");
            throw new Exception("The hashAlgorithmOID chosen is not supported by the TSA.");
        }
        // validate if the hashAlgorithmOID is a supported digestAlgorithm
        try {
            DSSService.getDigestAlgorithmFromOID(hashAlgorithmOID);
        } catch (Exception e){
            fileLogger.error("It was impossible to retrieve the hashAlgorithmOID requested. {}", e.getMessage());
            throw new Exception("The hashAlgorithmOID in the request is invalid.");
        }

        // validate the data in the documents
        if(documents == null || documents.isEmpty()){
            fileLogger.error("The documents values is missing.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                  "The documents to be signed should be sent in the request.");
        }
        for (DocumentsSignDocRequest doc: documents){
            try{
                doc.isValid();
            }catch (Exception e){
                fileLogger.error(e.getMessage());
                throw e;
            }
        }
    }

    private SignatureDocumentForm getSignatureForm(DocumentsSignDocRequest document, String hashAlgorithmOID,
          X509Certificate certificate, Date date, CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain) throws Exception{

        DSSDocument dssDocument = dssClient.loadDssDocument(document.getDocument(), document.getDocument_name());

        SignaturePackaging signaturePackaging;
        ASiCContainerType asicContainerType;
        SignatureLevel signatureLevel;
        DigestAlgorithm digestAlgorithm;
        SignatureForm signatureFormat;
        try {
            signaturePackaging = DSSService.getSignaturePackaging(document.getSigned_envelope_property());
            asicContainerType = DSSService.getASiCContainerType(document.getContainer());
            signatureLevel = DSSService.getSignatureLevel(document.getConformance_level(), document.getSignature_format());
            digestAlgorithm = DSSService.getDigestAlgorithmFromOID(hashAlgorithmOID);
            signatureFormat = DSSService.getSignatureForm(document.getSignature_format());
        }catch (Exception e){
            fileLogger.error("There was an error when trying to retrieve the required information for the SignatureDocumentForm from the information received. {}", e.getMessage());
            throw e;
        }

        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());

        SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
        signatureDocumentForm.setDocumentToSign(dssDocument);
        signatureDocumentForm.setSignaturePackaging(signaturePackaging);
        signatureDocumentForm.setContainerType(asicContainerType);
        signatureDocumentForm.setSignatureLevel(signatureLevel);
        signatureDocumentForm.setDigestAlgorithm(digestAlgorithm);
        signatureDocumentForm.setSignatureForm(signatureFormat);
        signatureDocumentForm.setCertificate(certificate);
        signatureDocumentForm.setDate(date);
        signatureDocumentForm.setTrustedCertificates(certificateSource);
        signatureDocumentForm.setSignatureForm(signatureFormat);
        signatureDocumentForm.setCertChain(certificateChain);
        signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);

        return signatureDocumentForm;
    }

    private String getSignedDocumentString(DocumentsSignDocRequest document, DSSDocument docSigned) throws Exception{
        try {
            if (document.getContainer().equals("ASiC-E")) {
                if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-e+zip"));
                }
            } else if (document.getContainer().equals("ASiC-S")) {
                if (document.getSignature_format().equals("C") || document.getSignature_format().equals("X")) {
                    docSigned.setMimeType(MimeType.fromMimeTypeString("application/vnd.etsi.asic-s+zip"));
                }
            } else if (document.getSignature_format().equals("J")) {
                docSigned.setMimeType(MimeType.fromMimeTypeString("application/jose"));
            } else if (document.getSignature_format().equals("X")) {
                docSigned.setMimeType(MimeType.fromMimeTypeString("text/xml"));
            } else {
                docSigned.setMimeType(MimeType.fromMimeTypeString("application/pdf"));
            }
        } catch (Exception e) {
            fileLogger.error("invalid request: {}", e.getMessage());
            throw e;
        }
        return Base64.getEncoder().encodeToString(docSigned.openStream().readAllBytes());
    }
}
