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

package eu.europa.ec.eudi.signer.r4.sca.model.oauth2;

import eu.europa.ec.eudi.signer.r4.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r4.sca.model.QTSPClient;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.oauth2.AuthorizeRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.oauth2.TokenRequest;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OAuth2Service {
	private final QTSPClient qtspClient;
	private final OAuthClientConfig oAuthClientConfig;
	private static final Logger logger = LoggerFactory.getLogger(OAuth2Service.class);

	public OAuth2Service(@Autowired QTSPClient qtspClient,
						 @Autowired OAuthClientConfig oAuthClientConfig) {
		this.qtspClient = qtspClient;
		this.oAuthClientConfig = oAuthClientConfig;
	}

	private String generateNonce(String root) throws Exception{
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		byte[] result = sha.digest(root.getBytes());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
	}

	public String getOAuth2AuthorizeAuthenticationLocation(
		  String authorizationServerUrl, String credentialId, String numSignatures, String hash, String hashAlgorithmOID,
		  String state, String code_verifier) throws Exception {

		// generate code_challenge, code_challenge_method, code_verifier
		String code_challenge = generateNonce(code_verifier);

		AuthorizeRequest authorizeRequest = new AuthorizeRequest();
		authorizeRequest.setResponse_type("code");
		authorizeRequest.setClient_id(this.oAuthClientConfig.getClientId());
		authorizeRequest.setRedirect_uri(this.oAuthClientConfig.getRedirectUri());
		authorizeRequest.setScope(this.oAuthClientConfig.getScope());
		authorizeRequest.setCode_challenge(code_challenge);
		authorizeRequest.setCode_challenge_method("S256");
		authorizeRequest.setLang("pt-PT");
		authorizeRequest.setState(state);
		authorizeRequest.setCredentialID(URLEncoder.encode(credentialId, StandardCharsets.UTF_8));
		authorizeRequest.setNumSignatures(numSignatures);
		authorizeRequest.setHashes(hash);
		authorizeRequest.setHashAlgorithmOID(hashAlgorithmOID);

		String asUrl;
		if(authorizationServerUrl == null)
			asUrl = this.oAuthClientConfig.getAuthorizationServerUrl();
		else asUrl = authorizationServerUrl;

		return this.qtspClient.requestOAuth2Authorize(asUrl, authorizeRequest);
	}

	private static String getBasicAuthenticationHeader(String username, String password) {
		String valueToEncode = username + ":" + password;
		return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
	}

	private JSONObject getOAuth2Token(String authorizationServerUrl, String code, String codeVerifier) throws Exception {
		logger.info("Making request to QTSP as client_id: {}", this.oAuthClientConfig.getClientId());
		String authorizationHeader = getBasicAuthenticationHeader(this.oAuthClientConfig.getClientId(), this.oAuthClientConfig.getClientSecret());

		TokenRequest tokenRequest = new TokenRequest();
		tokenRequest.setGrant_type(this.oAuthClientConfig.getAuthorizationGrantTypes());
		tokenRequest.setCode(code);
		tokenRequest.setClient_id(this.oAuthClientConfig.getClientId());
		tokenRequest.setRedirect_uri(this.oAuthClientConfig.getRedirectUri());
		tokenRequest.setCode_verifier(codeVerifier);

		logger.info("Making the following request to QTSP: {}", tokenRequest);
		return this.qtspClient.requestOAuth2Token(authorizationServerUrl, authorizationHeader, tokenRequest);
	}

	public String getOAuth2AccessToken(String authorizationServerUrl, String code, String codeVerifier) throws Exception{
		String asUrl;
		if(authorizationServerUrl == null)
			asUrl = this.oAuthClientConfig.getAuthorizationServerUrl();
		else asUrl = authorizationServerUrl;

		logger.info("Retrieving access token from Authorization Server {}, with code {}", asUrl, code);
		JSONObject oauth2TokenResponse = getOAuth2Token(asUrl, code, codeVerifier);
		if(!oauth2TokenResponse.has("access_token")){
			logger.error("Access token missing from OAuth2 Token Response.");
			throw new Exception("Access token missing from OAuth2 Token Response.");
		}
		return "Bearer "+oauth2TokenResponse.getString("access_token");
	}
}
