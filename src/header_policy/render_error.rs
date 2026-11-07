use crate::header_policy::template_variable::TemplateVariable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RenderError {
    Missing(TemplateVariable),
    InvalidValue,
}
