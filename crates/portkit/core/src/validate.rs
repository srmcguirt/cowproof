//! Boundary validation: check a call against the tool's declared schema
//! *before* dispatch.
//!
//! Without this, `input_schema` is advisory — documentation the runtime never
//! checks. That fails in the specific way that matters for agents: an invented
//! argument is silently accepted, the tool returns success, and the model
//! concludes the argument did something. A hallucination that gets a 200 is
//! worse than one that gets an error, because nothing corrects it.
//!
//! Validators are compiled once at registration, not per call.

use jsonschema::Validator;
use serde_json::Value;

use crate::error::Error;

/// A tool's compiled input schema.
pub struct InputValidator {
    tool: String,
    validator: Option<Validator>,
    /// Kept alongside the compiled form: schema-reference checking walks the
    /// raw document, which `jsonschema` does not expose once compiled.
    schema: Value,
}

impl InputValidator {
    /// Compile a tool's schema.
    ///
    /// An uncompilable schema disables validation for that tool rather than
    /// refusing to register it: a malformed schema is the author's bug, and
    /// taking the whole registry down for it would be a worse failure.
    pub fn compile(tool: &str, schema: &Value) -> Self {
        let validator = match jsonschema::validator_for(schema) {
            Ok(v) => Some(v),
            Err(err) => {
                tracing::warn!(
                    tool,
                    %err,
                    "input_schema does not compile; validation disabled for this tool"
                );
                None
            }
        };
        Self {
            tool: tool.to_string(),
            validator,
            schema: schema.clone(),
        }
    }

    /// The raw schema, for schema-reference checking.
    ///
    /// `jsonschema` does not expose the source document once compiled, and the
    /// reference walk needs it.
    pub fn schema(&self) -> &Value {
        &self.schema
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Check an argument object, returning an error the model can act on.
    pub fn check(&self, input: &Value) -> crate::Result<()> {
        let Some(validator) = &self.validator else {
            return Ok(());
        };
        if validator.is_valid(input) {
            return Ok(());
        }

        // Report every problem at once. Returning them one at a time costs a
        // full round trip per mistake.
        let mut problems: Vec<String> = validator
            .iter_errors(input)
            .map(|e| {
                let path = e.instance_path().to_string();
                let at = if path.is_empty() {
                    String::new()
                } else {
                    format!("{path}: ")
                };
                format!("{at}{e}")
            })
            .collect();
        problems.sort();
        problems.dedup();
        problems.truncate(10);

        Err(Error::invalid_input(&self.tool, problems.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" },
                "size": { "type": "integer", "minimum": 1 }
            },
            "required": ["text"],
            "additionalProperties": false
        })
    }

    #[test]
    fn a_valid_call_passes() {
        let v = InputValidator::compile("t", &schema());
        assert!(v.check(&json!({"text": "hi", "size": 4})).is_ok());
    }

    #[test]
    fn an_invented_argument_is_rejected() {
        // The motivating bug: an argument the schema never declared used to
        // sail through and the tool returned success.
        let v = InputValidator::compile("t", &schema());
        let err = v.check(&json!({"text": "hi", "bogus": 99})).unwrap_err();
        assert!(err.to_string().contains("bogus"), "got: {err}");
        assert!(err.is_caller_fault());
    }

    #[test]
    fn a_wrong_type_is_rejected() {
        let v = InputValidator::compile("t", &schema());
        assert!(v.check(&json!({"text": "hi", "size": "four"})).is_err());
    }

    #[test]
    fn a_missing_required_field_is_rejected() {
        let v = InputValidator::compile("t", &schema());
        assert!(v.check(&json!({"size": 4})).is_err());
    }

    #[test]
    fn a_constraint_violation_is_rejected() {
        let v = InputValidator::compile("t", &schema());
        assert!(v.check(&json!({"text": "hi", "size": 0})).is_err());
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        // One round trip per mistake is a bad trade when the model could fix
        // all of them from a single reply.
        let v = InputValidator::compile("t", &schema());
        let err = v
            .check(&json!({"size": "four", "bogus": 1}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("bogus"), "got: {err}");
        assert!(
            err.matches(';').count() >= 1,
            "expected several problems: {err}"
        );
    }

    #[test]
    fn an_uncompilable_schema_disables_validation_instead_of_failing_closed() {
        let v = InputValidator::compile("t", &json!({"type": "not-a-real-type"}));
        assert!(v.check(&json!({"anything": true})).is_ok());
    }
}
