package eu.europa.ec.eudi.signer.r4.sca.web.config;

import eu.europa.ec.eudi.signer.r4.sca.exception.SCAException;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

	public record ErrorDetailWithField(String code, String message, String field) {}

	public record ErrorDetail(String code, String message) {}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
		FieldError error = ex.getBindingResult().getFieldErrors().get(0);
		String field = error.getField();
		String constraint = error.getCode();

		ErrorDetailWithField detail = switch (constraint) {
			case "NotNull", "NotBlank" -> new ErrorDetailWithField(
				  "MISSING_PARAMETER",
				  error.getDefaultMessage(),
				  field
			);
			case "NotEmpty" -> new ErrorDetailWithField(
				  "EMPTY_PARAMETER",
				  error.getDefaultMessage(),
				  field
			);
			case "Valid" -> new ErrorDetailWithField(
				  "INVALID_PARAMETER",
				  error.getDefaultMessage(),
				  field
			);
			default -> new ErrorDetailWithField(
				  "VALIDATION_ERROR",
				  error.getDefaultMessage(),
				  field
			);
		};

		Map<String, Object> errors = new HashMap<>();
		errors.put("error", detail);
		return ResponseEntity.badRequest().body(errors);
	}

	@ExceptionHandler(SCAException.class)
	public ResponseEntity<Map<String, Object>> handleSCAExceptions(SCAException ex) {
		Map<String, Object> errors = new HashMap<>();
		if(ex.hasField()) {
			ErrorDetailWithField detail = new ErrorDetailWithField(ex.getErrorCode(), ex.getMessage(), ex.getField());
			errors.put("error", detail);
		}
		else {
			ErrorDetail detail = new ErrorDetail(ex.getErrorCode(), ex.getMessage());
			errors.put("error", detail);
		}
		return ResponseEntity.badRequest().body(errors);
	}

}