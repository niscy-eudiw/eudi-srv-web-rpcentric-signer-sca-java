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

package eu.europa.ec.eudi.signer.r4.sca.client;

import eu.europa.ec.eudi.signer.r4.sca.config.OAuthClientConfig;
import eu.europa.ec.eudi.signer.r4.sca.exception.SCAException.*;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.credentials.credentialsInfo.CredentialsInfoRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.credentials.credentialsInfo.CredentialsInfoResponse;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.oauth2.AuthorizeRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.oauth2.TokenRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signHash.SignHashRequest;
import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signHash.SignHashResponse;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class QTSPClient {
    private static final Logger log = LoggerFactory.getLogger(QTSPClient.class);
	private final OAuthClientConfig oAuthClientConfig;

	public QTSPClient(@Autowired OAuthClientConfig oAuthClientConfig) {
		this.oAuthClientConfig = oAuthClientConfig;
	}

	private WebClient webClient(String url){
		return WebClient.builder()
			  .baseUrl(url)
			  .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
			  .build();
	}

	public CredentialsInfoResponse requestCredentialInfo(String resourceServerUrl, String authorizationHeader,
														 CredentialsInfoRequest credentialsInfoRequest) throws CertificateChainCouldNotBeRetrieved {
        if(resourceServerUrl == null) resourceServerUrl = this.oAuthClientConfig.getResourceServerUrl();

		log.info("Making request to {}/csc/v2/credentials/info.", resourceServerUrl);
        log.debug("Request Body: {}", credentialsInfoRequest);

		return webClient(resourceServerUrl).post()
			  .uri("/csc/v2/credentials/info")
			  .bodyValue(credentialsInfoRequest)
			  .header("Authorization", authorizationHeader)
			  .retrieve()
			  .onStatus(
					HttpStatusCode :: isError,
					response -> response.bodyToMono(String.class)
						  .map(body -> {
							  log.error(body);
							  return new CertificateChainCouldNotBeRetrieved(
									"There was an error obtaining the certificate."
							  );
						  })
			  )
			  .bodyToMono(CredentialsInfoResponse.class)
			  .block();
	}

    public SignHashResponse requestSignHash(String resourceServerUrl, String authorizationHeader, SignHashRequest signHashRequest) {
		if(resourceServerUrl == null) resourceServerUrl = this.oAuthClientConfig.getResourceServerUrl();

		log.info("Making request to {}/csc/v2/signatures/signHash.", resourceServerUrl);
        log.debug("Request Body: {}", signHashRequest);

		return webClient(resourceServerUrl).post()
			  .uri("/csc/v2/signatures/signHash")
			  .bodyValue(signHashRequest)
			  .header("Authorization", authorizationHeader)
			  .retrieve()
			  .onStatus(
					HttpStatusCode :: isError,
					response -> response.bodyToMono(String.class)
						  .map(body -> {
							  log.error(body);
							  return new SignatureHashCouldNotBeRetrieved(
									"There was an error obtaining the signature of the hashes."
							  );
						  })
			  )
			  .bodyToMono(SignHashResponse.class)
			  .block();
    }

    public String requestOAuth2Authorize(String authorizeServerUrl, AuthorizeRequest authorizeRequest) throws Exception {
		log.info("Making request to {}/oauth2/authorize.", authorizeServerUrl);
        try(CloseableHttpClient httpClient = HttpClientBuilder.create().disableRedirectHandling().build()) {
            // {as_url}/oauth2/authorize
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                  .fromUriString(authorizeServerUrl)
                  .pathSegment("oauth2")
                  .pathSegment("authorize");

            uriBuilder
                  .queryParam("response_type", authorizeRequest.getResponse_type())
                  .queryParam("client_id", authorizeRequest.getClient_id())
                  .queryParamIfPresent("redirect_uri", Optional.ofNullable(authorizeRequest.getRedirect_uri()))
                  .queryParamIfPresent("scope", Optional.ofNullable(authorizeRequest.getScope()))
                  .queryParam("code_challenge", Optional.ofNullable(authorizeRequest.getCode_challenge()))
                  .queryParamIfPresent("code_challenge_method", Optional.ofNullable(authorizeRequest.getCode_challenge_method()))
                  .queryParamIfPresent("state", Optional.ofNullable(authorizeRequest.getState()))
                  .queryParamIfPresent("lang", Optional.ofNullable(authorizeRequest.getLang()))
                  .queryParamIfPresent("description", Optional.ofNullable(authorizeRequest.getDescription()))
                  .queryParamIfPresent("account_token", Optional.ofNullable(authorizeRequest.getAccount_token()))
                  .queryParamIfPresent("clientData", Optional.ofNullable(authorizeRequest.getClientData()))
                  .queryParamIfPresent("authorization_details", Optional.ofNullable(authorizeRequest.getAuthorization_details()))
                  .queryParamIfPresent("credentialID", Optional.ofNullable(authorizeRequest.getCredentialID()))
                  .queryParamIfPresent("signatureQualifier", Optional.ofNullable(authorizeRequest.getSignatureQualifier()))
                  .queryParamIfPresent("numSignatures", Optional.ofNullable(authorizeRequest.getNumSignatures()))
                  .queryParamIfPresent("hashes", Optional.ofNullable(authorizeRequest.getHashes()))
                  .queryParamIfPresent("hashAlgorithmOID", Optional.ofNullable(authorizeRequest.getHashAlgorithmOID()));

            String uri = uriBuilder.build().toString();
            HttpGet request = new HttpGet(uri);
            HttpResponse response = httpClient.execute(request);

			log.info("OAuth2 Authorize Endpoint Status Code: {}", response.getStatusLine().getStatusCode());

            if(response.getStatusLine().getStatusCode() == 302) {
                String location = response.getLastHeader("Location").getValue();
                log.info("Retrieved the authentication url: {}", location);
                return location;
            }
			else{
				log.error("It wasn't impossible to retrieve QTSP Web Page where to authorize signature.");
				throw new Exception("There was an error trying to obtain the credential authorization. Please try again.");
			}
        }
    }

    public JSONObject requestOAuth2Token(String authorizeServerUrl, String authorizationHeader, TokenRequest tokenRequest) throws Exception{
		log.info("Making request to {}/oauth2/token.", authorizeServerUrl);

		try(CloseableHttpClient httpClient2 = HttpClientBuilder.create().build()) {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                  .fromUriString(authorizeServerUrl)
                  .pathSegment("oauth2")
                  .pathSegment("token");

            uriBuilder
                  .queryParam("grant_type", tokenRequest.getGrant_type())
                  .queryParam("code", tokenRequest.getCode())
                  .queryParamIfPresent("refresh_token", Optional.ofNullable(tokenRequest.getRefresh_token()))
                  .queryParam("client_id", tokenRequest.getClient_id())
                  .queryParamIfPresent("client_secret", Optional.ofNullable(tokenRequest.getClient_secret()))
                  .queryParamIfPresent("client_assertion", Optional.ofNullable(tokenRequest.getClient_assertion()))
                  .queryParamIfPresent("client_assertion_type", Optional.ofNullable(tokenRequest.getClient_assertion_type()))
                  .queryParamIfPresent("redirect_uri", Optional.ofNullable(tokenRequest.getRedirect_uri()))
                  .queryParamIfPresent("authorization_details", Optional.ofNullable(tokenRequest.getAuthorization_details()))
                  .queryParam("code_verifier", tokenRequest.getCode_verifier());

            String url = uriBuilder.build().toString();
            HttpPost followRequest = new HttpPost(url);
            followRequest.setHeader(org.apache.http.HttpHeaders.AUTHORIZATION, authorizationHeader);

            HttpResponse followResponse = httpClient2.execute(followRequest);
			log.info("OAuth2 Token Endpoint Status Code: {}", followResponse.getStatusLine().getStatusCode());

			if(followResponse.getStatusLine().getStatusCode() == 200) {
				InputStream is = followResponse.getEntity().getContent();
				BufferedReader reader = new BufferedReader(new InputStreamReader(is));
				StringBuilder sb = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					sb.append(line).append("\n");
				}
				is.close();
				String responseString = sb.toString();
				return new JSONObject(responseString);
			}
			else {
				InputStream errorStream = followResponse.getEntity().getContent();
				BufferedReader errorReader = new BufferedReader(new InputStreamReader(errorStream));
				StringBuilder errorSb = new StringBuilder();
				String errorLine;
				while ((errorLine = errorReader.readLine()) != null) {
					errorSb.append(errorLine).append("\n");
				}
				errorStream.close();
				String errorResponse = errorSb.toString();

				log.error("It wasn't possible to successfully complete the oauth2/token.");
				log.error("OAuth2 Token Endpoint returned non-200 status code: {}", followResponse.getStatusLine().getStatusCode());
				log.error("Error response body: {}", errorResponse);

				throw new Exception("It wasn't possible to successfully complete the oauth2/token. Response code: "
					  + followResponse.getStatusLine().getStatusCode() + ". Body: " + errorResponse);
			}
        }
    }
}
