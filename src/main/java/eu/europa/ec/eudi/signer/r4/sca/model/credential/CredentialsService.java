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

package eu.europa.ec.eudi.signer.r4.sca.model.credential;

import eu.europa.ec.eudi.signer.r4.sca.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.signer.r4.sca.exception.SCAException.*;
import eu.europa.ec.eudi.signer.r4.sca.exception.SCAException.CertificateChainCouldNotBeRetrieved;
import eu.europa.ec.eudi.signer.r4.sca.exception.SCAException.CertificateBase64DecodingException;
import eu.europa.ec.eudi.signer.r4.sca.client.QTSPClient;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.credentials.credentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.credentials.credentialsInfo.CredentialsInfoResponse;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class CredentialsService {
    private final QTSPClient qtspClient;
    private final CertificateToken TSACertificateToken;
    private final TimestampAuthorityConfig timestampAuthorityConfig;
    private static final Logger logger = LoggerFactory.getLogger(CredentialsService.class);

    public CredentialsService(@Autowired QTSPClient qtspClient,
                              @Autowired TimestampAuthorityConfig timestampAuthorityConfig) throws MisconfigurationException{
        this.qtspClient = qtspClient;
        this.timestampAuthorityConfig = timestampAuthorityConfig;

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            String certificateStringPath = timestampAuthorityConfig.getCertificatePath();
            if (certificateStringPath == null || certificateStringPath.isEmpty()) {
                throw new MisconfigurationException("Timestamp authority certificate path not found in configuration.", "timestamp-authority.certificate-path");
            }
            FileInputStream certInput = new FileInputStream(certificateStringPath);
            X509Certificate TSACertificate = (X509Certificate) certFactory.generateCertificate(certInput);
            this.TSACertificateToken = new CertificateToken(TSACertificate);
            certInput.close();
        }
        catch (CertificateException e){
            String message = "Failed to generate timestamp authority X.509 certificate. Certificate may be invalid or corrupted.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new MisconfigurationException(message, "timestamp-authority.certificate-path");
        } catch (FileNotFoundException e) {
            String message = "Failed to find the timestamp authority X.509 certificate file.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new MisconfigurationException(message, "timestamp-authority.certificate-path");
        } catch (IOException e) {
            String message = "Unexpected error when loading the timestamp authority certificate.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new MisconfigurationException(message, "timestamp-authority.certificate-path");
        }

    }

    public static class CertificateResponse {
        private X509Certificate certificate;
        private final List<X509Certificate> certificateChain;
        private CommonTrustedCertificateSource tsaCommonSource;
        private final List<String> signAlgo;

        public CertificateResponse(X509Certificate certificate, List<X509Certificate> certificateChain,
                                   List<String> signAlgo) {
            this.certificate = certificate;
            this.certificateChain = certificateChain;
            this.signAlgo = signAlgo;
        }

        public X509Certificate getCertificate() {
            return certificate;
        }

        public void setCertificate(X509Certificate certificate) {
            this.certificate = certificate;
        }

        public List<X509Certificate> getCertificateChain() {
            return certificateChain;
        }

        public CommonTrustedCertificateSource getTsaCommonSource() {
            return tsaCommonSource;
        }

        public void setTsaCommonSource(CommonTrustedCertificateSource tsaCommonSource) {
            this.tsaCommonSource = tsaCommonSource;
        }

        public List<String> getSignAlgo() {
            return signAlgo;
        }

    }

    // validate if the hashAlgorithmOID is supported by the TSA
    public void checkHashAlgorithmOIDSupportedByTSA(String hashAlgorithmOID) throws HashAlgorithmOIDInvalidException {
        if(!this.timestampAuthorityConfig.getSupportedDigestAlgorithm().contains(hashAlgorithmOID)){
            String message = String.format("The hash algorithm OID '%s' is not supported by the TSA. Supported OIDs: %s",
                  hashAlgorithmOID, timestampAuthorityConfig.getSupportedDigestAlgorithm());
            logger.error(message);
            throw new HashAlgorithmOIDInvalidException("The hashAlgorithmOID chosen is not supported by the TSA.");
        }
    }

    public CertificateResponse getCertificateAndChainAndCommonSource(String resourceServerUrl, String accessToken, String credentialId)
          throws CertificateChainCouldNotBeRetrieved, CertificateBase64DecodingException {
        CertificateResponse response = getCertificateAndCertificateChain(resourceServerUrl, credentialId, accessToken);
        logger.info("Retrieved the signing certificate and the certificate chain.");

        CommonTrustedCertificateSource commonTrustedCertificateSource = getCommonTrustedCertificateSource();
        response.setTsaCommonSource(commonTrustedCertificateSource);
        logger.info("Retrieved the certificate source.");
        return response;
    }

    // get the certificate and certificate chain of the credentialID
    private CertificateResponse getCertificateAndCertificateChain(String resourceServerUrl, String credentialId, String authorizationHeader) throws CertificateChainCouldNotBeRetrieved, CertificateBase64DecodingException {
        CredentialsInfoRequest infoRequest = new CredentialsInfoRequest(credentialId, "chain", true);

        CredentialsInfoResponse infoResponse = this.qtspClient.requestCredentialInfo(resourceServerUrl, authorizationHeader, infoRequest);
        logger.info("Successfully retrieved certificates from {}", resourceServerUrl);

        List<String> certificates = infoResponse.getCert().getCertificates();
        List<String> keyAlgo = infoResponse.getKey().getAlgo();

        List<X509Certificate> x509Certificates = new ArrayList<>();
        for(String c: certificates){
            X509Certificate cert = base64DecodeCertificate(c);
            logger.info("{}: {}", cert.getSubjectX500Principal(), cert.getSerialNumber());
            x509Certificates.add(cert);
        }
        return new CertificateResponse(x509Certificates.get(0), x509Certificates.subList(1, x509Certificates.size()), keyAlgo);
    }

    private X509Certificate base64DecodeCertificate(String certificate) throws CertificateBase64DecodingException {
        try {
            byte[] certificateBytes = Base64.getDecoder().decode(certificate);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificateDecoded = (X509Certificate) certFactory.generateCertificate(inputStream);
            logger.info("Successfully decoded X.509 certificate. Subject: {}", certificateDecoded.getSubjectX500Principal());
            return certificateDecoded;
        } catch (IllegalArgumentException e) {
            String message = "Failed to decode the provided certificate. Input is not valid Base64.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new CertificateBase64DecodingException(message);

        } catch (CertificateException e) {
            String message = "Failed to generate X.509 certificate from decoded bytes. Certificate may be invalid or corrupted.";
            logger.error("{} Error: {}", message, e.getMessage(), e);
            throw new CertificateBase64DecodingException(message);
        }
    }

    public CommonTrustedCertificateSource getCommonTrustedCertificateSource(){
        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
        certificateSource.addCertificate(this.TSACertificateToken);
        return certificateSource;
    }
}
