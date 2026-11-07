#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemplateVariable {
    ClientIp,
    ClientPort,
    RequestId,
    Scheme,
    Host,
    Method,
}

impl TemplateVariable {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "client_ip" => Some(Self::ClientIp),
            "client_port" => Some(Self::ClientPort),
            "request_id" => Some(Self::RequestId),
            "scheme" => Some(Self::Scheme),
            "host" => Some(Self::Host),
            "method" => Some(Self::Method),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_parse() {
        assert_eq!(
            TemplateVariable::parse("client_ip"),
            Some(TemplateVariable::ClientIp)
        );
        assert_eq!(
            TemplateVariable::parse("method"),
            Some(TemplateVariable::Method)
        );
    }

    #[test]
    fn unknown_name_is_none() {
        assert_eq!(TemplateVariable::parse("nope"), None);
        assert_eq!(TemplateVariable::parse("Client_Ip"), None);
    }
}
