//! The exact price of an OpenRouter model, read from OpenRouter itself (D28 step 2).
//!
//! OpenCode computes the cost of each model call from the price in the lane's config, the meter
//! reads that figure, and the cost cap acts on it. So the cap is only as true as the price. The
//! director therefore fetches `GET <upstream>/api/v1/models` once, at preflight, with the real
//! key (this is the director's own request: it does not pass through the lane's proxy), finds
//! each rung's model by its exact id, and hands the price down. There is no table of guessed
//! prices and no fallback price: a model that is not listed, or a list that cannot be fetched or
//! read, ends the run before a lane exists.
//!
//! Fields read from a model object (OpenRouter's API reference, `GET /models`):
//!
//! * `id`, matched exactly and case-sensitively;
//! * `pricing.prompt` and `pricing.completion`, required; `pricing.input_cache_read` and
//!   `pricing.input_cache_write`, optional. These are USD PER TOKEN, as decimal strings. They are
//!   converted to USD per million tokens, the unit OpenCode's config uses, by moving the decimal
//!   point in the text ([`per_million`]), never by multiplying a float, so `"0.00000123"` is
//!   exactly `1.23`;
//! * `context_length` and `top_provider.max_completion_tokens`, optional (OpenRouter sends
//!   `null` for some models). When one is absent the lane's config gets [`DEFAULT_CONTEXT`] or
//!   [`DEFAULT_OUTPUT`], and the record says so in `defaulted`. A field that is present but not a
//!   positive whole number is an error, not an absence.
//!
//! A cache price that is absent is priced as the plain input price (a model that lists no cache
//! discount has none), and the record says so as well.

use crate::proxy::{Upstream, https_client};
use anyhow::{Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The path of OpenRouter's model list. Also what a record's `source` says.
pub const MODELS_PATH: &str = "/api/v1/models";
/// The most response bytes read from the list.
pub const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
/// How long the whole request (connect, headers, body) may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// The context window used when a model lists none. OpenCode needs both limits to schedule
/// compaction; they are conservative.
pub const DEFAULT_CONTEXT: u64 = 128_000;
/// The output limit used when a model lists none.
pub const DEFAULT_OUTPUT: u64 = 16_000;

/// Token prices in USD per MILLION tokens, and the model's limits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPrice {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
    pub context: u64,
    pub output_limit: u64,
}

/// One model's price as fetched, with where and when it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct PriceRecord {
    pub price: ModelPrice,
    /// The path that was fetched; never the host and never the key.
    pub source: String,
    /// UTC, RFC 3339, to the second.
    pub fetched_at: String,
    /// The fields the list did not give, so a default stands in: any of `contextLength`,
    /// `maxOutput`, `cacheRead` and `cacheWrite`.
    pub defaulted: Vec<&'static str>,
}

impl PriceRecord {
    /// The record as `run.json` and the capsule hold it.
    pub fn to_json(&self) -> Value {
        json!({
            "inputPerMillion": self.price.input,
            "outputPerMillion": self.price.output,
            "cacheReadPerMillion": self.price.cache_read,
            "cacheWritePerMillion": self.price.cache_write,
            "contextLength": self.price.context,
            "maxOutput": self.price.output_limit,
            "defaulted": self.defaulted,
            "source": self.source,
            "fetchedAt": self.fetched_at,
        })
    }
}

/// Why a model has no price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriceError {
    /// The list could not be fetched or read at all (network, HTTP status, JSON, size, time).
    Fetch(String),
    /// The list was read and does not hold the id.
    NotListed(String),
    /// The id is listed and its entry cannot be used.
    Unusable { model: String, why: String },
}

impl fmt::Display for PriceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(why) => write!(
                f,
                "OpenRouter's model list could not be read ({why}); the cost cap cannot be enforced without a price"
            ),
            Self::NotListed(model) => write!(
                f,
                "model {model:?} is not in OpenRouter's model list (ids are matched exactly); the cost cap cannot be enforced without a price"
            ),
            Self::Unusable { model, why } => write!(
                f,
                "model {model:?} has no usable price in OpenRouter's model list ({why}); the cost cap cannot be enforced without a price"
            ),
        }
    }
}

impl std::error::Error for PriceError {}

/// A price given per token, as OpenRouter writes it, in USD per million tokens.
///
/// The grammar is `digits[.digits][e|E[+-]digits]`: no sign, no spaces, no `inf` or `nan`, no
/// hex. A leading `-` is refused as negative. Scientific notation is accepted although
/// OpenRouter has been seen to send plain decimals only: it costs nothing to read a valid
/// number that way. The decimal point is moved in the text (six places for "per million") and
/// the result is read by Rust's correctly rounded float parser, so the nearest double to the
/// intended decimal comes out.
pub fn per_million(text: &str) -> Result<f64, String> {
    if text.starts_with('-') {
        return Err(format!("{text:?} is negative"));
    }
    let bad = || format!("{text:?} is not a decimal number");
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(i) => (&text[..i], Some(&text[i + 1..])),
        None => (text, None),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (mantissa, ""),
    };
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if whole.is_empty()
        || !digits(whole)
        || !digits(fraction)
        || (mantissa.contains('.') && fraction.is_empty())
    {
        return Err(bad());
    }
    let exponent: i32 = match exponent {
        None => 0,
        Some(e) => {
            let (negative, body) = match e.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, e.strip_prefix('+').unwrap_or(e)),
            };
            if body.is_empty() || body.len() > 4 || !digits(body) {
                return Err(bad());
            }
            let value: i32 = body.parse().map_err(|_| bad())?;
            if negative { -value } else { value }
        }
    };
    let all = format!("{whole}{fraction}");
    let significant = all.trim_start_matches('0');
    if significant.is_empty() {
        return Ok(0.0);
    }
    if significant.len() > 40 {
        return Err(format!("{text:?} has too many digits"));
    }
    let shift = exponent - fraction.len() as i32 + 6;
    let value: f64 = format!("{significant}e{shift}")
        .parse()
        .map_err(|_| bad())?;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(format!("{text:?} is out of range"))
    }
}

/// A limit field: absent or `null` is `None`; a positive whole number is `Some`; anything else
/// is an error naming the field.
fn limit(value: Option<&Value>, name: &str) -> Result<Option<u64>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) if n > 0 => Ok(Some(n)),
            _ => Err(format!("{name} is {v}, not a positive whole number")),
        },
    }
}

/// A price field of `pricing`: required ones are an error when missing.
fn price_field(pricing: &Value, name: &str, required: bool) -> Result<Option<f64>, String> {
    match pricing.get(name) {
        None | Some(Value::Null) if !required => Ok(None),
        None | Some(Value::Null) => Err(format!("pricing.{name} is missing")),
        Some(Value::String(text)) => per_million(text)
            .map(Some)
            .map_err(|e| format!("pricing.{name}: {e}")),
        Some(other) => Err(format!("pricing.{name} is {other}, not a string")),
    }
}

/// The record for `model` in a `GET /models` body. `fetched_at` is stamped into the record.
pub fn price_from_list(
    body: &[u8],
    model: &str,
    fetched_at: &str,
) -> Result<PriceRecord, PriceError> {
    let list: Value = serde_json::from_slice(body)
        .map_err(|e| PriceError::Fetch(format!("the response is not JSON: {e}")))?;
    let entries = list
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| PriceError::Fetch("the response has no `data` list".to_string()))?;
    let mut found = entries
        .iter()
        .filter(|m| m.get("id").and_then(Value::as_str) == Some(model));
    let entry = found
        .next()
        .ok_or_else(|| PriceError::NotListed(model.to_string()))?;
    let unusable = |why: String| PriceError::Unusable {
        model: model.to_string(),
        why,
    };
    if found.next().is_some() {
        return Err(unusable("it is listed more than once".to_string()));
    }
    let pricing = entry
        .get("pricing")
        .filter(|p| p.is_object())
        .ok_or_else(|| unusable("it has no `pricing` object".to_string()))?;
    let input = price_field(pricing, "prompt", true)
        .map_err(&unusable)?
        .unwrap_or_default();
    let output = price_field(pricing, "completion", true)
        .map_err(&unusable)?
        .unwrap_or_default();
    let cache_read = price_field(pricing, "input_cache_read", false).map_err(&unusable)?;
    let cache_write = price_field(pricing, "input_cache_write", false).map_err(&unusable)?;
    let context = limit(entry.get("context_length"), "context_length").map_err(&unusable)?;
    let max_output = limit(
        entry
            .get("top_provider")
            .and_then(|p| p.get("max_completion_tokens")),
        "top_provider.max_completion_tokens",
    )
    .map_err(&unusable)?;

    let mut defaulted = Vec::new();
    let mut or_default = |value: Option<u64>, default: u64, name: &'static str| {
        value.unwrap_or_else(|| {
            defaulted.push(name);
            default
        })
    };
    let context = or_default(context, DEFAULT_CONTEXT, "contextLength");
    let output_limit = or_default(max_output, DEFAULT_OUTPUT, "maxOutput");
    let mut or_input = |value: Option<f64>, name: &'static str| {
        value.unwrap_or_else(|| {
            defaulted.push(name);
            input
        })
    };
    let cache_read = or_input(cache_read, "cacheRead");
    let cache_write = or_input(cache_write, "cacheWrite");
    Ok(PriceRecord {
        price: ModelPrice {
            input,
            output,
            cache_read,
            cache_write,
            context,
            output_limit,
        },
        source: MODELS_PATH.to_string(),
        fetched_at: fetched_at.to_string(),
        defaulted,
    })
}

/// `secs` since the Unix epoch as `YYYY-MM-DDThh:mm:ssZ` (UTC), by the civil-from-days
/// algorithm, so no date library is needed for one timestamp.
pub fn rfc3339_utc(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now_utc() -> String {
    rfc3339_utc(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

/// `GET <upstream>/api/v1/models` with `Authorization: Bearer <key>`: the body, at most
/// [`MAX_LIST_BYTES`], within `timeout` for the whole exchange. Any other status is an error.
/// The key is in the request and in no message.
pub async fn fetch_list(upstream: &str, key: &str, timeout: Duration) -> Result<Vec<u8>> {
    let target = Upstream::parse(upstream)?.target(MODELS_PATH)?;
    let mut authorization = HeaderValue::from_str(&format!("Bearer {key}"))
        .map_err(|_| anyhow::anyhow!("the OpenRouter key is not a valid header value"))?;
    authorization.set_sensitive(true);
    let request = Request::builder()
        .method(Method::GET)
        .uri(target)
        .header(header::AUTHORIZATION, authorization)
        .header(header::ACCEPT, "application/json")
        .body(Empty::<Bytes>::new())?;
    let client = https_client::<Empty<Bytes>>();
    let exchange = async {
        let response = client.request(request).await?;
        let status = response.status();
        if status != StatusCode::OK {
            bail!("HTTP status {}", status.as_u16());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                if bytes.len() + data.len() > MAX_LIST_BYTES {
                    bail!("the response is larger than {MAX_LIST_BYTES} bytes");
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => bail!("no complete response within {} ms", timeout.as_millis()),
    }
}

/// The price of every model in `models` (exact ids), from one fetch. An error list holds one
/// [`PriceError::Fetch`] when the list itself could not be had, else one error per model that
/// has no usable price. Nothing partial is returned: a run needs them all.
pub async fn fetch_prices(
    upstream: &str,
    key: &str,
    models: &[String],
    timeout: Duration,
) -> Result<BTreeMap<String, PriceRecord>, Vec<PriceError>> {
    let body = fetch_list(upstream, key, timeout)
        .await
        .map_err(|e| vec![PriceError::Fetch(format!("{e:#}"))])?;
    prices_from_list(&body, models, &now_utc())
}

/// [`fetch_prices`] on a body already in hand.
pub fn prices_from_list(
    body: &[u8],
    models: &[String],
    fetched_at: &str,
) -> Result<BTreeMap<String, PriceRecord>, Vec<PriceError>> {
    let mut prices = BTreeMap::new();
    let mut errors = Vec::new();
    for model in models {
        match price_from_list(body, model, fetched_at) {
            Ok(record) => {
                prices.insert(model.clone(), record);
            }
            Err(e @ PriceError::Fetch(_)) => return Err(vec![e]),
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(prices)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(models: Value) -> Vec<u8> {
        json!({ "data": models }).to_string().into_bytes()
    }

    fn glm(prompt: &str, completion: &str) -> Value {
        json!({
            "id": "z-ai/glm-5.3-flash",
            "context_length": 202_752,
            "top_provider": {"max_completion_tokens": 65_535},
            "pricing": {"prompt": prompt, "completion": completion},
        })
    }

    #[test]
    fn per_token_text_becomes_per_million_exactly() {
        for (text, want) in [
            ("0.00000123", 1.23),
            ("0.00000456", 4.56),
            ("0.0000006", 0.6),
            ("0.0000022", 2.2),
            ("0", 0.0),
            ("0.0", 0.0),
            ("0.000000", 0.0),
            ("1", 1_000_000.0),
            ("0.000001", 1.0),
            ("12.5", 12_500_000.0),
            // Scientific notation: OpenRouter sends plain decimals, but `1.23e-6` is a valid
            // decimal and is read the same way.
            ("1.23e-6", 1.23),
            ("4.56E-06", 4.56),
            ("123e-8", 1.23),
            ("1e-6", 1.0),
            ("5e+1", 50_000_000.0),
        ] {
            assert_eq!(per_million(text), Ok(want), "{text}");
        }
    }

    #[test]
    fn negative_and_non_numeric_prices_are_refused() {
        assert!(per_million("-0.000001").unwrap_err().contains("negative"));
        assert!(per_million("-0").unwrap_err().contains("negative"));
        for bad in [
            "", ".", ".5", "5.", "abc", "1,5", " 1", "1 ", "+1", "0x10", "inf", "NaN", "1e", "1e+",
            "1e5.5", "e5", "1e99999", "1__0",
        ] {
            assert!(per_million(bad).is_err(), "{bad:?} must be refused");
        }
        // 41 significant digits.
        assert!(per_million(&format!("0.{}", "1".repeat(41))).is_err());
        // A double cannot hold it.
        assert!(per_million("1e400").unwrap_err().contains("range"));
    }

    #[test]
    fn a_model_is_found_by_its_exact_id_and_priced_per_million() {
        let body = list(json!([glm("0.00000123", "0.00000456")]));
        let record = price_from_list(&body, "z-ai/glm-5.3-flash", "2026-10-11T00:00:00Z").unwrap();
        assert_eq!(record.price.input, 1.23);
        assert_eq!(record.price.output, 4.56);
        assert_eq!(record.price.context, 202_752);
        assert_eq!(record.price.output_limit, 65_535);
        assert_eq!(record.source, "/api/v1/models");
        assert_eq!(record.fetched_at, "2026-10-11T00:00:00Z");
        // No cache price was listed: both are the plain input price, and the record says so.
        assert_eq!(record.price.cache_read, 1.23);
        assert_eq!(record.price.cache_write, 1.23);
        assert_eq!(record.defaulted, ["cacheRead", "cacheWrite"]);
        let json = record.to_json();
        assert_eq!(json["inputPerMillion"], 1.23);
        assert_eq!(json["maxOutput"], 65_535);
        assert_eq!(json["defaulted"], json!(["cacheRead", "cacheWrite"]));
    }

    #[test]
    fn listed_cache_prices_are_used_and_not_marked_defaulted() {
        let mut model = glm("0.0000006", "0.0000022");
        model["pricing"]["input_cache_read"] = json!("0.00000011");
        model["pricing"]["input_cache_write"] = json!("0.00000075");
        let record = price_from_list(&list(json!([model])), "z-ai/glm-5.3-flash", "now").unwrap();
        assert_eq!(record.price.cache_read, 0.11);
        assert_eq!(record.price.cache_write, 0.75);
        assert!(record.defaulted.is_empty(), "{:?}", record.defaulted);
    }

    #[test]
    fn a_missing_limit_falls_back_and_the_record_says_so() {
        let mut model = glm("0.000001", "0.000002");
        // `null` is how OpenRouter says "not known".
        model["top_provider"] = json!({"max_completion_tokens": null});
        model.as_object_mut().unwrap().remove("context_length");
        let record = price_from_list(&list(json!([model])), "z-ai/glm-5.3-flash", "now").unwrap();
        assert_eq!(record.price.context, DEFAULT_CONTEXT);
        assert_eq!(record.price.output_limit, DEFAULT_OUTPUT);
        assert_eq!(
            record.defaulted,
            ["contextLength", "maxOutput", "cacheRead", "cacheWrite"]
        );
        // No `top_provider` at all is the same absence.
        let mut model = glm("0.000001", "0.000002");
        model.as_object_mut().unwrap().remove("top_provider");
        let record = price_from_list(&list(json!([model])), "z-ai/glm-5.3-flash", "now").unwrap();
        assert_eq!(record.price.output_limit, DEFAULT_OUTPUT);
        assert!(record.defaulted.contains(&"maxOutput"));
        // A present limit that is not a positive whole number is an error, not an absence.
        for bad in [json!("65535"), json!(0), json!(-5), json!(1.5)] {
            let mut model = glm("0.000001", "0.000002");
            model["top_provider"]["max_completion_tokens"] = bad;
            let e =
                price_from_list(&list(json!([model])), "z-ai/glm-5.3-flash", "now").unwrap_err();
            assert!(matches!(e, PriceError::Unusable { .. }), "{e}");
        }
    }

    #[test]
    fn an_id_is_matched_exactly_never_by_substring_or_case() {
        let body = list(json!([
            {"id": "z-ai/glm-5.3", "pricing": {"prompt": "0.000001", "completion": "0.000002"}},
            {"id": "z-ai/glm-5.3-flash-lite", "pricing": {"prompt": "0.000001", "completion": "0.000002"}},
            {"id": "Z-AI/GLM-5.3-FLASH", "pricing": {"prompt": "0.000001", "completion": "0.000002"}},
        ]));
        // The rung names a model that only a shorter, a longer and a differently cased id match.
        let e = price_from_list(&body, "z-ai/glm-5.3-flash", "now").unwrap_err();
        assert_eq!(e, PriceError::NotListed("z-ai/glm-5.3-flash".to_string()));
        assert!(e.to_string().contains("z-ai/glm-5.3-flash"));
        assert!(price_from_list(&body, "z-ai/glm-5.3", "now").is_ok());
    }

    #[test]
    fn unusable_entries_are_refused_naming_the_cause() {
        let cases = [
            (glm("-0.000001", "0.000002"), "negative"),
            (glm("0.000001", "free"), "not a decimal"),
            (json!({"id": "z-ai/glm-5.3-flash"}), "no `pricing` object"),
            (
                json!({"id": "z-ai/glm-5.3-flash", "pricing": {"prompt": "0.000001"}}),
                "pricing.completion is missing",
            ),
            (
                json!({"id": "z-ai/glm-5.3-flash", "pricing": {"prompt": 1e-6, "completion": "0.000002"}}),
                "not a string",
            ),
            // The router models list -1 for "varies".
            (glm("-1", "-1"), "negative"),
        ];
        for (model, why) in cases {
            let e =
                price_from_list(&list(json!([model])), "z-ai/glm-5.3-flash", "now").unwrap_err();
            match &e {
                PriceError::Unusable { model, why: got } => {
                    assert_eq!(model, "z-ai/glm-5.3-flash");
                    assert!(got.contains(why), "{got} should contain {why}");
                }
                other => panic!("{other:?}"),
            }
            assert!(e.to_string().contains("cost cap cannot be enforced"));
        }
        // Listed twice is ambiguous.
        let twice = list(json!([
            glm("0.000001", "0.000002"),
            glm("0.000001", "0.000002")
        ]));
        assert!(matches!(
            price_from_list(&twice, "z-ai/glm-5.3-flash", "now"),
            Err(PriceError::Unusable { .. })
        ));
    }

    #[test]
    fn a_body_that_is_not_a_model_list_is_a_fetch_error() {
        for body in [&b"not json"[..], b"{}", b"[]", br#"{"data": 5}"#, b""] {
            let e = price_from_list(body, "m", "now").unwrap_err();
            assert!(matches!(e, PriceError::Fetch(_)), "{body:?}: {e}");
            assert!(e.to_string().contains("cost cap cannot be enforced"));
        }
        // And it stops the whole batch with one error.
        let errors =
            prices_from_list(b"nope", &["a".to_string(), "b".to_string()], "now").unwrap_err();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn every_model_without_a_price_is_reported_and_nothing_partial_is_returned() {
        let body = list(json!([glm("0.000001", "0.000002")]));
        let models = [
            "z-ai/glm-5.3-flash".to_string(),
            "acme/one".to_string(),
            "acme/two".to_string(),
        ];
        let errors = prices_from_list(&body, &models, "now").unwrap_err();
        assert_eq!(
            errors,
            [
                PriceError::NotListed("acme/one".to_string()),
                PriceError::NotListed("acme/two".to_string())
            ]
        );
        let prices = prices_from_list(&body, &models[..1], "now").unwrap();
        assert_eq!(prices.len(), 1);
        assert_eq!(prices["z-ai/glm-5.3-flash"].price.input, 1.0);
    }

    #[test]
    fn timestamps_are_utc_rfc3339() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }
}
