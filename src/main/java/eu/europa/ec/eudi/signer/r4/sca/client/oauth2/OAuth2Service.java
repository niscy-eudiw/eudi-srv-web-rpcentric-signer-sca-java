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

package eu.europa.ec.eudi.signer.r4.sca.client.oauth2;

import eu.europa.ec.eudi.signer.r4.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r4.sca.client.QTSPClient;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.oauth2.AuthorizeRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

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

	private String generateNonce(String codeChallengeMethod, String root) throws Exception{
		if(codeChallengeMethod.equals("S256")) {
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			byte[] result = sha.digest(root.getBytes());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
		}
		else {
			return Base64.getUrlEncoder().withoutPadding().encodeToString(root.getBytes());
		}
	}

	public String getOAuth2AuthorizeAuthenticationLocation(String authorizationServerUrl, String credentialId,
														   List<String> hashes, String hashAlgorithmOID,
														   String state, String code_verifier) throws Exception {
		AuthorizeRequest authorizeRequest = new AuthorizeRequest();

		authorizeRequest.setResponse_type(URLEncoder.encode("code", StandardCharsets.UTF_8));
		authorizeRequest.setClient_id(URLEncoder.encode(this.oAuthClientConfig.getClientId(), StandardCharsets.UTF_8));
		authorizeRequest.setRedirect_uri(URLEncoder.encode(this.oAuthClientConfig.getRedirectUri(), StandardCharsets.UTF_8));
		authorizeRequest.setScope(URLEncoder.encode(this.oAuthClientConfig.getScope(), StandardCharsets.UTF_8));
		authorizeRequest.setLang(URLEncoder.encode("pt-PT", StandardCharsets.UTF_8));
		authorizeRequest.setState(URLEncoder.encode(state, StandardCharsets.UTF_8));
		authorizeRequest.setCredentialID(URLEncoder.encode(credentialId, StandardCharsets.UTF_8));
		authorizeRequest.setHashAlgorithmOID(URLEncoder.encode(hashAlgorithmOID, StandardCharsets.UTF_8));

		String numSignatures = Integer.toString(hashes.size());
		authorizeRequest.setNumSignatures(URLEncoder.encode(numSignatures, StandardCharsets.UTF_8));

		List<String> base64URLEncodedString = new ArrayList<>();
		for(String h: hashes) {
			byte[] bytes = Base64.getDecoder().decode(h);
			String base64urlEncoded = Base64.getUrlEncoder().encodeToString(bytes);
			logger.info(base64urlEncoded);
			base64URLEncodedString.add(URLEncoder.encode(base64urlEncoded, StandardCharsets.UTF_8));
		}
		String hash = String.join(",", base64URLEncodedString);
		authorizeRequest.setHashes(hash);

		// generate code_challenge, code_challenge_method, code_verifier
		String code_challenge = generateNonce("S256", code_verifier);
		authorizeRequest.setCode_challenge(URLEncoder.encode(code_challenge, StandardCharsets.UTF_8));
		authorizeRequest.setCode_challenge_method(URLEncoder.encode("S256", StandardCharsets.UTF_8));

		if(authorizationServerUrl == null) authorizationServerUrl = this.oAuthClientConfig.getAuthorizationServerUrl();
		return this.qtspClient.requestOAuth2Authorize(authorizationServerUrl, authorizeRequest);
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

	public String getOAuth2AccessToken(String authorizationServerUrl, String code, String codeVerifier) throws Exception {
		if(authorizationServerUrl == null) authorizationServerUrl = this.oAuthClientConfig.getAuthorizationServerUrl();

		logger.info("Retrieving access token from Authorization Server {}, with code {}", authorizationServerUrl, code);
		JSONObject oauth2TokenResponse = getOAuth2Token(authorizationServerUrl, code, codeVerifier);
		if(!oauth2TokenResponse.has("access_token")){
			logger.error("Access token missing from OAuth2 Token Response.");
			throw new Exception("There was an error trying to obtain the credential authorization. Please try again.");
		}
		return "Bearer "+oauth2TokenResponse.getString("access_token");
	}
}
