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

package eu.europa.ec.eudi.signer.r4.sca.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "timestamp-authority")
public class TimestampAuthorityConfig {
	private String certificatePath;
	private String serverUrl;
	private List<String> supportedDigestAlgorithm;

	public String getCertificatePath() {
		return certificatePath;
	}

	public void setCertificatePath(String certificatePath) {
		this.certificatePath = certificatePath;
	}

	public String getServerUrl() {
		return serverUrl;
	}

	public void setServerUrl(String serverUrl) {
		this.serverUrl = serverUrl;
	}

	public List<String> getSupportedDigestAlgorithm() {
		return supportedDigestAlgorithm;
	}

	public void setSupportedDigestAlgorithm(List<String> supportedDigestAlgorithm) {
		this.supportedDigestAlgorithm = supportedDigestAlgorithm;
	}
}
