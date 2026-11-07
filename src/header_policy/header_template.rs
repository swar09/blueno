use std::fmt::Write;

use axum::http::HeaderValue;

use crate::header_policy::header_policy_error::HeaderPolicyError;
use crate::header_policy::render_error::RenderError;
use crate::header_policy::request_context::RequestContext;
use crate::header_policy::template_variable::TemplateVariable;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Variable(TemplateVariable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Repr {
    Static(HeaderValue),
    Dynamic(Vec<Segment>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderTemplate {
    repr: Repr,
}

impl HeaderTemplate {
    pub fn parse(name: &str, raw: &str) -> Result<Self, HeaderPolicyError> {
        let invalid = |reason: &'static str| HeaderPolicyError::InvalidTemplate {
            name: name.to_string(),
            reason,
        };
        let mut segments: Vec<Segment> = Vec::new();
        let mut literal = String::new();
        let mut chars = raw.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    literal.push('{');
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal.push('}');
                }
                '}' => return Err(invalid("stray '}' (use '}}' for a literal brace)")),
                '{' => {
                    let mut variable = String::new();
                    let mut closed = false;
                    for next in chars.by_ref() {
                        if next == '}' {
                            closed = true;
                            break;
                        }
                        variable.push(next);
                    }
                    if !closed {
                        return Err(invalid("unclosed '{' (use '{{' for a literal brace)"));
                    }
                    let Some(parsed) = TemplateVariable::parse(&variable) else {
                        return Err(HeaderPolicyError::UnknownVariable {
                            name: name.to_string(),
                            variable,
                        });
                    };
                    if !literal.is_empty() {
                        segments.push(Segment::Literal(std::mem::take(&mut literal)));
                    }
                    segments.push(Segment::Variable(parsed));
                }
                other => literal.push(other),
            }
        }
        if segments.is_empty() {
            return HeaderValue::from_str(&literal)
                .map(|value| Self {
                    repr: Repr::Static(value),
                })
                .map_err(|_| HeaderPolicyError::InvalidValue {
                    name: name.to_string(),
                });
        }
        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        Ok(Self {
            repr: Repr::Dynamic(segments),
        })
    }

    pub fn is_static(&self) -> bool {
        matches!(self.repr, Repr::Static(_))
    }

    pub fn render(&self, context: &RequestContext) -> Result<HeaderValue, RenderError> {
        let segments = match &self.repr {
            Repr::Static(value) => return Ok(value.clone()),
            Repr::Dynamic(segments) => segments,
        };
        let mut out = String::new();
        for segment in segments {
            match segment {
                Segment::Literal(text) => out.push_str(text),
                Segment::Variable(variable) => Self::write_variable(&mut out, *variable, context)?,
            }
        }
        HeaderValue::from_str(&out).map_err(|_| RenderError::InvalidValue)
    }

    fn write_variable(
        out: &mut String,
        variable: TemplateVariable,
        context: &RequestContext,
    ) -> Result<(), RenderError> {
        let missing = RenderError::Missing(variable);
        match variable {
            TemplateVariable::ClientIp => {
                let ip = context.client_ip.ok_or(missing)?;
                let _ = write!(out, "{ip}");
            }
            TemplateVariable::ClientPort => {
                let port = context.client_port.ok_or(missing)?;
                let _ = write!(out, "{port}");
            }
            TemplateVariable::RequestId => {
                out.push_str(context.request_id.as_deref().ok_or(missing)?);
            }
            TemplateVariable::Scheme => out.push_str(&context.scheme),
            TemplateVariable::Host => {
                out.push_str(context.host.as_deref().ok_or(missing)?);
            }
            TemplateVariable::Method => out.push_str(&context.method),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_context() -> RequestContext {
        RequestContext {
            client_ip: Some("203.0.113.5".parse().expect("valid ip")),
            client_port: Some(4000),
            request_id: Some("rid-1".to_string()),
            scheme: "https".to_string(),
            host: Some("example.com".to_string()),
            method: "GET".to_string(),
            ..Default::default()
        }
    }

    fn render(raw: &str, context: &RequestContext) -> Result<HeaderValue, RenderError> {
        HeaderTemplate::parse("x-test", raw)
            .expect("valid template")
            .render(context)
    }

    #[test]
    fn literal_only_is_static() {
        let template = HeaderTemplate::parse("x-test", "blueno").expect("valid");
        assert_eq!(
            template.repr,
            Repr::Static(HeaderValue::from_static("blueno"))
        );
        assert_eq!(
            template.render(&RequestContext::default()),
            Ok(HeaderValue::from_static("blueno"))
        );
    }

    #[test]
    fn single_variable_renders() {
        assert_eq!(
            render("{client_ip}", &full_context()),
            Ok(HeaderValue::from_static("203.0.113.5"))
        );
    }

    #[test]
    fn mixed_template_renders() {
        assert_eq!(
            render("for={client_ip}:{client_port}", &full_context()),
            Ok(HeaderValue::from_static("for=203.0.113.5:4000"))
        );
    }

    #[test]
    fn all_variables_render() {
        assert_eq!(
            render("{request_id} {scheme} {host} {method}", &full_context()),
            Ok(HeaderValue::from_static("rid-1 https example.com GET"))
        );
    }

    #[test]
    fn doubled_braces_are_literal() {
        let template = HeaderTemplate::parse("x-test", "{{literal}}").expect("valid");
        assert_eq!(
            template.repr,
            Repr::Static(HeaderValue::from_static("{literal}"))
        );
    }

    #[test]
    fn unknown_variable_is_error() {
        let result = HeaderTemplate::parse("x-test", "{nope}");
        assert!(matches!(
            result,
            Err(HeaderPolicyError::UnknownVariable { ref variable, .. }) if variable == "nope"
        ));
    }

    #[test]
    fn unclosed_brace_is_error() {
        let result = HeaderTemplate::parse("x-test", "a{client_ip");
        assert!(matches!(
            result,
            Err(HeaderPolicyError::InvalidTemplate { .. })
        ));
    }

    #[test]
    fn stray_closing_brace_is_error() {
        let result = HeaderTemplate::parse("x-test", "a}b");
        assert!(matches!(
            result,
            Err(HeaderPolicyError::InvalidTemplate { .. })
        ));
    }

    #[test]
    fn invalid_static_value_is_error() {
        let result = HeaderTemplate::parse("x-test", "line\nbreak");
        assert!(matches!(
            result,
            Err(HeaderPolicyError::InvalidValue { .. })
        ));
    }

    #[test]
    fn missing_client_ip_is_skipped() {
        let context = RequestContext {
            client_ip: None,
            ..full_context()
        };
        assert_eq!(
            render("{client_ip}", &context),
            Err(RenderError::Missing(TemplateVariable::ClientIp))
        );
    }

    #[test]
    fn invalid_rendered_value_is_error() {
        let context = RequestContext {
            host: Some("bad\nhost".to_string()),
            ..full_context()
        };
        assert_eq!(render("{host}", &context), Err(RenderError::InvalidValue));
    }
}
