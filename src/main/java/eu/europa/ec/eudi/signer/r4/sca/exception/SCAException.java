/*
 Copyright 2026 European Commission

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

package eu.europa.ec.eudi.signer.r4.sca.exception;

public abstract class SCAException extends Exception {
	private final String errorCode;
	private final String field; // Optional, can be null

	public SCAException(String errorCode, String message) {
		super(message);
		this.errorCode = errorCode;
		this.field = null;
	}

	public SCAException(String errorCode, String message, String field) {
		super(message);
		this.errorCode = errorCode;
		this.field = field;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getField() {
		return field;
	}

	public boolean hasField() {
		return field != null;
	}

	public static class CertificateBase64DecodingException extends SCAException {
		public CertificateBase64DecodingException(String message) {
			super("INVALID_BASE64_CERTIFICATE", message);
		}
	}

	public static class CertificateChainCouldNotBeRetrieved extends SCAException {
		public CertificateChainCouldNotBeRetrieved(String message) {
			super("CERTIFICATE_NOT_FOUND", message);
		}
	}

	public static class SignatureHashCouldNotBeRetrieved extends SCAException {
		public SignatureHashCouldNotBeRetrieved(String message) {
			super("MISSING_SIGNATURE", message);
		}
	}

	public static class DocumentSignatureCountMismatchException extends SCAException {
		public DocumentSignatureCountMismatchException(String message) {
			super("DOCUMENT_SIGNATURE_COUNT_MISMATCH", message);
		}
	}

	public static class DocumentSignDocParameterInvalidException extends SCAException {
		public DocumentSignDocParameterInvalidException(String message, String invalid_parameter_name) {
			super("INVALID_PARAMETER", message, invalid_parameter_name);
		}
	}

	public static class HashAlgorithmOIDInvalidException extends SCAException {
		public HashAlgorithmOIDInvalidException(String message) {
			super("INVALID_HASH_ALGORITHM_OID", message, "hashAlgorithmOID");
		}
	}

	public static class MisconfigurationException extends SCAException {
		public MisconfigurationException(String message, String configuration_parameter) {
			super("PROJECT_MISCONFIGURATION", message, configuration_parameter);
		}
	}

	public static class UnsupportedSignatureFormatException extends SCAException {
		public UnsupportedSignatureFormatException(String message) {
			super("UNSUPPORTED_SIGNATURE_FORMAT", message);
		}
	}


}
