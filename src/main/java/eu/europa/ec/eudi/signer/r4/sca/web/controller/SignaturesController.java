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

package eu.europa.ec.eudi.signer.r4.sca.web.controller;

import eu.europa.ec.eudi.signer.r4.sca.model.credential.CredentialsService;
import eu.europa.ec.eudi.signer.r4.sca.web.session.SessionState;
import eu.europa.ec.eudi.signer.r4.sca.model.signature.SignatureService;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.SignatureDocumentRequest;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;

import org.springframework.security.core.session.SessionRegistry;

@Controller
@RequestMapping(value = "/signatures")
public class SignaturesController {
    private static final Logger logger = LoggerFactory.getLogger(SignaturesController.class);
    private final SignatureService signatureService;
    private final CredentialsService credentialsService;
    private final SessionRegistry sessionRegistry;

    public SignaturesController(@Autowired SignatureService signatureService, @Autowired CredentialsService credentialsService, @Autowired SessionRegistry sessionRegistry) {
        this.signatureService = signatureService;
        this.credentialsService = credentialsService;
        this.sessionRegistry = sessionRegistry;
    }

    @PostMapping(value="/doc", consumes = "application/json")
    public String signatureDoc(@RequestHeader(name="Authorization") String authorizationBearerHeader, @Valid @RequestBody SignatureDocumentRequest signatureRequest, HttpSession session) throws Exception {
        logger.info("Request received to sign a document.");
        logger.debug("Request body: {}", signatureRequest);

        SessionState sessionState = new SessionState();

        String hashAlgorithmOID = signatureRequest.getHashAlgorithmOID();
        this.credentialsService.checkHashAlgorithmOIDSupportedByTSA(hashAlgorithmOID);
        this.signatureService.validateHashAlgorithmOID(hashAlgorithmOID);
        sessionState.setHashAlgorithmOID(hashAlgorithmOID);
        logger.info("Successfully validated request to /signatures/doc.");

        String authorizationServerUrl = signatureRequest.getAuthorizationServerUrl();
        sessionState.setAuthorizationServerUrl(authorizationServerUrl);

        String resourceServerUrl = signatureRequest.getResourceServerUrl();
        sessionState.setResourceServerUrl(resourceServerUrl);

        String credentialID = signatureRequest.getCredentialID();
        sessionState.setCredentialID(credentialID);
        sessionState.setDocuments(signatureRequest.getDocuments());
        sessionState.setRedirectUri(signatureRequest.getRedirectUri());

        CredentialsService.CertificateResponse certificates =
              this.credentialsService.getCertificateAndChainAndCommonSource(resourceServerUrl, authorizationBearerHeader, credentialID);
        sessionState.setEndEntityCertificate(certificates.getCertificate());
        sessionState.setCertificateChain(certificates.getCertificateChain());
        sessionState.setSignAlgo(certificates.getSignAlgo().get(0));
        logger.info("Retrieved all the required certificates.");

        Date date = new Date();
        sessionState.setDate(date.getTime());

        String location = this.signatureService.getHashesAndOAuth2AuthorizeCredential(sessionState, session.getId(), authorizationServerUrl, credentialID,
              signatureRequest.getDocuments(), certificates.getCertificate(), certificates.getCertificateChain(),
              certificates.getTsaCommonSource(), hashAlgorithmOID, date);
        logger.info("Successfully retrieved oauth2 authorization url.");

        session.setAttribute("signatureState", sessionState);
        this.sessionRegistry.registerNewSession(session.getId(), session);

        return "redirect:"+location;
    }

    @GetMapping(value="/callback")
    public String credentialAuthorizationCode(@RequestParam("code") String code, @RequestParam("state") String state, Model model) throws Exception {
        logger.info("Request received to continue signing a document.");

        SessionInformation sessionInformation = this.sessionRegistry.getSessionInformation(state);
        HttpSession session = (HttpSession) sessionInformation.getPrincipal();
        SessionState sessionState = (SessionState) session.getAttribute("signatureState");
        logger.info("Retrieved the session state.");

        CommonTrustedCertificateSource certificateSource = this.credentialsService.getCommonTrustedCertificateSource();
        logger.info("Loaded Certificate Source.");

        Date date = new Date(sessionState.getDate());
        List<String> signaturesResponse = this.signatureService.getAccessTokenAndSignDocument(sessionState.getAuthorizationServerUrl(), sessionState.getResourceServerUrl(),
              code, sessionState.getCodeVerifier(), sessionState.getDocuments(), sessionState.getHash(), sessionState.getCredentialID(),
              sessionState.getEndEntityCertificate(), sessionState.getCertificateChain(), certificateSource, sessionState.getSignAlgo(),
              sessionState.getHashAlgorithmOID(), date);
        logger.info("Obtained the documents signed.");

        String signed_document_base64 = signaturesResponse.get(0);
        String redirect_uri = sessionState.getRedirectUri();

        model.addAttribute("url",  redirect_uri);
        model.addAttribute("body", signed_document_base64);
        return "successful_authentication";
    }
}
