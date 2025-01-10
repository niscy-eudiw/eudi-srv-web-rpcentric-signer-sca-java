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

package eu.europa.ec.eudi.signer.r4.sca.web.dto;

import eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signDoc.DocumentsSignDocRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.List;

public class SignatureDocumentRequest {
    @NotBlank(message = "The credentialID must be present.")
    private String credentialID;

    @NotBlank(message = "The list of documents and configuration must be present.")
    private List<DocumentsSignDocRequest> documents;

    @NotBlank(message = "The hashAlgorithmOID must be defined.")
    @Pattern(regexp = "^\\d+\\.\\d+\\.\\d+(\\.\\d+)*+$", message = "Invalid parameter hashAlgorithmOID")
    private String hashAlgorithmOID;

    @Pattern(regexp = "^(https?|ftp):\\/\\/(\\S+(:\\S*)?@)?([\\w.-]+|\\[[\\dA-Fa-f:.]+])(\\:\\d+)?(\\/[-\\w@:%+.~#?&/=]*)?$",
          message = "Invalid authorization server URL")
    private String authorizationServerUrl;

    @Pattern(regexp = "^(https?|ftp):\\/\\/(\\S+(:\\S*)?@)?([\\w.-]+|\\[[\\dA-Fa-f:.]+])(\\:\\d+)?(\\/[-\\w@:%+.~#?&/=]*)?$",
          message = "Invalid resource server URL")
    private String resourceServerUrl;

    // url where to post the file and redirect after the end of the signature flow
    @NotBlank(message = "The redirectURI is required and is missing from the request.")
    @Pattern(regexp = "^(https?|ftp):\\/\\/(\\S+(:\\S*)?@)?([\\w.-]+|\\[[\\dA-Fa-f:.]+])(\\:\\d+)?(\\/[-\\w@:%+.~#?&/=]*)?$",
          message = "Invalid redirect URI")
    private String redirectUri;

    private String clientData;

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public List<DocumentsSignDocRequest> getDocuments() {
        return documents;
    }

    public void setDocuments(List<DocumentsSignDocRequest> documents) {
        this.documents = documents;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    public String getAuthorizationServerUrl() {
        return authorizationServerUrl;
    }

    public void setAuthorizationServerUrl(String authorizationServerUrl) {
        this.authorizationServerUrl = authorizationServerUrl;
    }

    public String getResourceServerUrl() {
        return resourceServerUrl;
    }

    public void setResourceServerUrl(String resourceServerUrl) {
        this.resourceServerUrl = resourceServerUrl;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Override
    public String toString() {
        return "CredentialAuthorizationRequest{" +
              "credentialID='" + credentialID + '\'' +
              ", documents=" + documents +
              ", hashAlgorithmOID='" + hashAlgorithmOID + '\'' +
              ", authorizationServerUrl='" + authorizationServerUrl + '\'' +
              ", resourceServerUrl='" + resourceServerUrl + '\'' +
              ", clientData='" + clientData + '\'' +
              '}';
    }
}
