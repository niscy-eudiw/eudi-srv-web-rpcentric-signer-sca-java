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

package eu.europa.ec.eudi.signer.r4.sca.web.dto.qtsp.signatures.signDoc;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import java.util.List;

public class DocumentsSignDocRequest {
    @Schema(description = "A base64-encoded document.", required = true)
    @NotBlank(message = "The document must be present in the request")
    private String document;
    @Schema(description = "The name of the document to be signed.")
    private String document_name;
    @Schema(description = "The digital signature format to use when signing the document.", required = true)
    @NotBlank(message = "Signature format cannot be blank")
    @Pattern(regexp = "P|C|X|J", message = "Invalid signature format")
    private String signature_format = null;
    @Schema(description = "The signature conformance level. The default level is AdES-B-B.", required = true)
    @Pattern(regexp = "Ades-B-B|Ades-B-T|Ades-B-LT|Ades-B-LTA|Ades-B|Ades-T|Ades-LT|Ades-LTA", message = "Invalid conformance level")
    private String conformance_level = "AdES-B-B";
    @Schema(description = "List of signed attributes.")
    private List<AttributeSignDocRequest> signed_props;
    @Schema(description = "The property concerning the signed envelope.", required = true)
    @Pattern(regexp = "ENVELOPED|ENVELOPING|DETACHED|INTERNALLY_DETACHED", message = "Invalid signed envelope property")
    private String signed_envelope_property;
    @Schema(description = "Specifies the signature container type. The default container is 'No'")
    @Pattern(regexp = "No|ASiC-E|ASiC-S", message = "Invalid container value")
    private String container = "No";

    public String getDocument() {
        return document;
    }

    public void setDocument(String document) {
        this.document = document;
    }

    public String getDocument_name() {
        return document_name;
    }

    public void setDocument_name(String document_name) {
        this.document_name = document_name;
    }

    public String getSignature_format() {
        return signature_format;
    }

    public void setSignature_format(String signature_format) {
        this.signature_format = signature_format;
    }

    public String getConformance_level() {
        return conformance_level;
    }

    public void setConformance_level(String conformance_level) {
        this.conformance_level = conformance_level;
    }

    public List<AttributeSignDocRequest> getSigned_props() {
        return signed_props;
    }

    public void setSigned_props(List<AttributeSignDocRequest> signed_props) {
        this.signed_props = signed_props;
    }

    public String getSigned_envelope_property() {
        return signed_envelope_property;
    }

    public void setSigned_envelope_property(String signed_envelope_property) {
        this.signed_envelope_property = signed_envelope_property;
    }

    public String getContainer() {
        return container;
    }

    public void setContainer(String container) {
        this.container = container;
    }

    @Override
    public String toString() {
        return "DocumentsSignDocRequest{" +
              "document='" + document + '\'' +
              ", document_name='" + document_name + '\'' +
              ", signature_format='" + signature_format + '\'' +
              ", conformance_level='" + conformance_level + '\'' +
              ", signed_props=" + signed_props +
              ", signed_envelope_property='" + signed_envelope_property + '\'' +
              ", container='" + container + '\'' +
              '}';
    }

    /**
     * Checks if a given signature format is valid.
     * The supported signature format are "P", "C", "X", "J"
     * @return true if is valid otherwise returns false
     */
    public boolean checkSignatureFormat(){
        return signature_format.equals("P") || signature_format.equals("X") ||
              signature_format.equals("J") || signature_format.equals("C");
    }

    /**
     * Checks if a given conformance level is valid.
     * @return true if is valid otherwise returns false
     */
    public boolean checkConformanceLevel(){
        return conformance_level.equals("Ades-B-B") ||
              conformance_level.equals("Ades-B-T") ||
              conformance_level.equals("Ades-B-LT") ||
              conformance_level.equals("Ades-B-LTA") ||
              conformance_level.equals("Ades-B") ||
              conformance_level.equals("Ades-T") ||
              conformance_level.equals("Ades-LT") ||
              conformance_level.equals("Ades-LTA");
    }

    public boolean checkSignedEnvelopeProperty(){
        return signed_envelope_property.equals("ENVELOPED") || signed_envelope_property.equals("ENVELOPING") ||
              signed_envelope_property.equals("DETACHED") || signed_envelope_property.equals("INTERNALLY_DETACHED");
    }

    public boolean checkContainer(){
        return container.equals("No") || container.equals("ASiC-E") || container.equals("ASiC-S");
    }

    public void isValid() throws Exception{
        if(!checkSignatureFormat())
            throw new Exception("The signature format is invalid.");
        if(!checkConformanceLevel())
            throw new Exception("The conformance level is invalid.");
        if(!checkSignedEnvelopeProperty())
            throw new Exception("The signed envelope property is invalid.");
        if(!checkContainer())
            throw new Exception("The container is invalid.");
    }

}
