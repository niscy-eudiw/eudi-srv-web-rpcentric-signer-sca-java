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

import eu.europa.ec.eudi.signer.r4.sca.client.oauth2.OAuth2Service;
import eu.europa.ec.eudi.signer.r4.sca.exception.SCAException.*;
import eu.europa.ec.eudi.signer.r4.sca.client.QTSPClient;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signDoc.DocumentsSignDocRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signHash.SignHashRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signHash.SignHashResponse;
import eu.europa.ec.eudi.signer.r4.sca.web.session.SessionState;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
public class SignatureService {
    private static final Logger logger = LoggerFactory.getLogger(SignatureService.class);
    private final OAuth2Service oAuth2Service;
    private final QTSPClient qtspClient;
    private final DSSService dssClient;

    public SignatureService(@Autowired OAuth2Service oAuth2Service, @Autowired QTSPClient qtspClient, @Autowired DSSService dssClient) {
        this.qtspClient = qtspClient;
        this.dssClient = dssClient;
        this.oAuth2Service = oAuth2Service;
    }

    public String getHashesAndOAuth2AuthorizeCredential(SessionState session, String sessionID, String authorizationServerUrl, String credentialID, List<DocumentsSignDocRequest> documents, X509Certificate certificate,
                                                        List<X509Certificate> certificateChain, CommonTrustedCertificateSource certificateSource,
                                                        String hashAlgorithmOID, Date date) throws Exception {

        List<String> hashes = calculateHashValue(documents, certificate, certificateChain, certificateSource, hashAlgorithmOID, date);
        session.setHash(hashes);
        logger.info("Obtained the list of hashes.");

        SecureRandom prng = new SecureRandom();
        String code_verifier = String.valueOf(prng.nextInt());
        session.setCodeVerifier(code_verifier);
        logger.info("Obtained the code verifier value.");

		return this.oAuth2Service.getOAuth2AuthorizeAuthenticationLocation(authorizationServerUrl, credentialID, hashes, hashAlgorithmOID, sessionID, code_verifier);
    }


    private List<String> calculateHashValue(List<DocumentsSignDocRequest> documents, X509Certificate certificate,
                                           List<X509Certificate> certificateChain, CommonTrustedCertificateSource certificateSource,
                                           String hashAlgorithmOID, Date date) throws DocumentSignDocParameterInvalidException, UnsupportedSignatureFormatException {

        List<String> hashes = new ArrayList<>();
        for (DocumentsSignDocRequest document : documents) {
            logger.info("Payload Received:{ Conformance Level:{}, Signature Format:{}, Hash Algorithm OID:{}, Signature Packaging:{}, Type of Container:{} }",
                  document.getConformance_level(), document.getSignature_format(), hashAlgorithmOID, document.getSigned_envelope_property(), document.getContainer());

            CommonTrustedCertificateSource certificateSourceCopy = createCopyCertificateSource(document, certificateSource, certificateChain);

            byte[] dataToBeSigned = dssClient.getDigestOfDataToBeSigned(document, hashAlgorithmOID, certificate, date, certificateSourceCopy, certificateChain);
            if (dataToBeSigned == null) continue;

            logger.info("Successfully created digest of data to be signed of a document.");

            String dataToBeSignedStringEncoded = Base64.getEncoder().encodeToString(dataToBeSigned);
            hashes.add(dataToBeSignedStringEncoded);
        }

        logger.info("Successfully created 'DataToBeSigned' for {} documents.", documents.size());
        return hashes;
    }

    public List<String> getAccessTokenAndSignDocument(String authorizationServer, String resourceServer, String code, String codeVerifier, List<DocumentsSignDocRequest> documents,
                                                      List<String> hashes, String credentialID, X509Certificate certificate, List<X509Certificate> certificateChain,
                                                      CommonTrustedCertificateSource certificateSource, String signAlgo, String hashAlgorithmOID, Date date) throws Exception {
        String access_token  = this.oAuth2Service.getOAuth2AccessToken(authorizationServer, code, codeVerifier);
        logger.info("Obtained Access Token with scope Credential.");

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
        SignHashResponse signHashResponse = qtspClient.requestSignHash(resourceServer, access_token, signHashRequest);
        List<String> signatureObjects = signHashResponse.getSignatures();
        if (signatureObjects.size() != documents.size()) {
            logger.error("The number of signatures received doesn't match the number of documents to signed received. " +
                  "Number of Document: {} & Number of Signatures: {}", documents.size(), signatureObjects.size());
            throw new DocumentSignatureCountMismatchException("The number of signatures received doesn't match the number of documents to signed received.");
        }

        List<String> signedDocuments = new ArrayList<>();
        for (int i = 0; i < documents.size(); i++) {
            DocumentsSignDocRequest document = documents.get(i);
            String signatureValue = signatureObjects.get(i);

            CommonTrustedCertificateSource certificateSourceCopy = createCopyCertificateSource(document, certificateSource, certificateChain);

            DSSDocument docSigned = dssClient.signDocument(document, hashAlgorithmOID, certificate, date, certificateSourceCopy, certificateChain, signatureValue);
            logger.info("Document successfully signed.");
            String signedDocumentString = getSignedDocumentString(document, docSigned);
            signedDocuments.add(signedDocumentString);
        }

        return signedDocuments;
    }

    public void validateHashAlgorithmOID(String hashAlgorithmOID) throws HashAlgorithmOIDInvalidException {
        // validate if the hashAlgorithmOID is a supported digestAlgorithm
        try {
            DSSService.getDigestAlgorithmFromOID(hashAlgorithmOID);
        } catch (DocumentSignDocParameterInvalidException e){
            String message = String.format("Failed to retrieve a digest algorithm for hashAlgorithmOID '%s'. Error: %s",
                  hashAlgorithmOID, e.getMessage());
            logger.error(message, e);
            throw new HashAlgorithmOIDInvalidException("The hashAlgorithmOID in the request is invalid.");
        }
        logger.debug("Hash Algorithm OID: {}", hashAlgorithmOID);
        logger.info("Successfully validated the hashAlgorithmOID received");
    }

    private CommonTrustedCertificateSource createCopyCertificateSource(DocumentsSignDocRequest document, CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain){
        CommonTrustedCertificateSource certificateSourceCopy = new CommonTrustedCertificateSource();
        certificateSource.getCertificates().forEach(certificateSourceCopy::addCertificate);
        if(document.getConformance_level().equals("Ades-B-LTA") || document.getConformance_level().equals("Ades-B-LT")){
            for (X509Certificate cert : certificateChain) {
                certificateSource.addCertificate(new CertificateToken(cert));
            }
        }
        return certificateSourceCopy;
    }

    private String getSignedDocumentString(DocumentsSignDocRequest document, DSSDocument docSigned) {
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

        InMemoryDocument signedDocument = new InMemoryDocument(DSSUtils.toByteArray(docSigned), docSigned.getName(), docSigned.getMimeType());
        return Base64.getEncoder().encodeToString(signedDocument.getBytes());
    }
}
