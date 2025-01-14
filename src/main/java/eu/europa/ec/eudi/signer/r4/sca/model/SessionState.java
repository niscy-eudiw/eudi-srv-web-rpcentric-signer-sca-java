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

package eu.europa.ec.eudi.signer.r4.sca.model;

import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signDoc.DocumentsSignDocRequest;

import java.security.cert.X509Certificate;
import java.util.List;

public class SessionState {

	private long date;
	private List<DocumentsSignDocRequest> documents;
	private List<String> hash;

	private String credentialID;
	private X509Certificate endEntityCertificate;
	private List<X509Certificate> certificateChain;
	private String signAlgo;

	private String hashAlgorithmOID;
	private String codeVerifier;

	private String authorizationServerUrl;
	private String resourceServerUrl;
	private String redirectUri;

	public long getDate() {
		return date;
	}

	public void setDate(long date) {
		this.date = date;
	}

	public List<DocumentsSignDocRequest> getDocuments() {
		return documents;
	}

	public void setDocuments(List<DocumentsSignDocRequest> documents) {
		this.documents = documents;
	}

	public List<String> getHash() {
		return hash;
	}

	public void setHash(List<String> hash) {
		this.hash = hash;
	}

	public String getCredentialID() {
		return credentialID;
	}

	public void setCredentialID(String credentialID) {
		this.credentialID = credentialID;
	}

	public X509Certificate getEndEntityCertificate() {
		return endEntityCertificate;
	}

	public void setEndEntityCertificate(X509Certificate endEntityCertificate) {
		this.endEntityCertificate = endEntityCertificate;
	}

	public List<X509Certificate> getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(List<X509Certificate> certificateChain) {
		this.certificateChain = certificateChain;
	}

	public String getSignAlgo() {
		return signAlgo;
	}

	public void setSignAlgo(String signAlgo) {
		this.signAlgo = signAlgo;
	}

	public String getHashAlgorithmOID() {
		return hashAlgorithmOID;
	}

	public void setHashAlgorithmOID(String hashAlgorithmOID) {
		this.hashAlgorithmOID = hashAlgorithmOID;
	}

	public String getCodeVerifier() {
		return codeVerifier;
	}

	public void setCodeVerifier(String codeVerifier) {
		this.codeVerifier = codeVerifier;
	}

	public String getResourceServerUrl() {
		return resourceServerUrl;
	}

	public void setResourceServerUrl(String resourceServerUrl) {
		this.resourceServerUrl = resourceServerUrl;
	}

	public String getAuthorizationServerUrl() {
		return authorizationServerUrl;
	}

	public void setAuthorizationServerUrl(String authorizationServerUrl) {
		this.authorizationServerUrl = authorizationServerUrl;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}
}
