//! What a Gateway's `spec` asks of Sōzune's addresses and infrastructure,
//! and what its status then says.
//!
//! Sōzune serves every Gateway on the addresses it publishes
//! (`publish_addresses` or `publish_service`). A Gateway may name some of
//! them in `spec.addresses`, and gets only those in its `status.addresses`;
//! one it names that Sōzune does not publish cannot be served. Sōzune has no
//! infrastructure parameters: a Gateway naming any in
//! `spec.infrastructure.parametersRef` is not accepted.

use gateway_api::apis::standard::gateways::Gateway;
use std::net::IpAddr;

const IP_ADDRESS: &str = "IPAddress";
const HOSTNAME: &str = "Hostname";

/// Why a Gateway's spec cannot be served as written.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum SpecIssue {
    /// `infrastructure.parametersRef` is set: Sōzune takes no parameters.
    InvalidParameters,
    /// An address of a type other than `IPAddress` and `Hostname`.
    UnsupportedAddress(String),
    /// An address of a type Sōzune publishes none of, its value left out.
    AddressNotAssigned(String),
    /// An address Sōzune does not publish.
    AddressNotUsable(String),
}

impl SpecIssue {
    /// Whether the Gateway is still accepted: only its addresses are not
    /// available.
    pub(super) fn accepted(&self) -> bool {
        matches!(
            self,
            Self::AddressNotAssigned(_) | Self::AddressNotUsable(_)
        )
    }

    /// The reason the condition the issue sets carries: `Accepted` when the
    /// Gateway is refused, `Programmed` otherwise.
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::InvalidParameters => "InvalidParameters",
            Self::UnsupportedAddress(_) => "UnsupportedAddress",
            Self::AddressNotAssigned(_) => "AddressNotAssigned",
            Self::AddressNotUsable(_) => "AddressNotUsable",
        }
    }

    pub(super) fn message(&self) -> String {
        match self {
            Self::InvalidParameters => {
                "infrastructure.parametersRef is not supported: Sōzune takes no parameters"
                    .to_string()
            }
            Self::UnsupportedAddress(t) => {
                format!("Address type {t} is not supported: only IPAddress and Hostname")
            }
            Self::AddressNotAssigned(t) => {
                format!("Sōzune publishes no {t} address to assign")
            }
            Self::AddressNotUsable(v) => {
                format!("Address {v} is not one Sōzune publishes")
            }
        }
    }
}

/// The `status.addresses` of `gateway`, as `(type, value)`, from Sōzune's
/// `published` ones (`None`: none are published, or not known yet), or
/// why its spec cannot be served. With no `spec.addresses`, the Gateway
/// gets every published address; otherwise only those it names, an
/// address of a type with no value getting every published one of that
/// type. `Ok(None)` leaves the status addresses alone.
pub(super) fn resolve(
    gateway: &Gateway,
    published: Option<&[(String, String)]>,
) -> Result<Option<Vec<(String, String)>>, SpecIssue> {
    if gateway
        .spec
        .infrastructure
        .as_ref()
        .is_some_and(|i| i.parameters_ref.is_some())
    {
        return Err(SpecIssue::InvalidParameters);
    }
    let requested = gateway.spec.addresses.as_deref().unwrap_or_default();
    if requested.is_empty() {
        return Ok(published.map(<[_]>::to_vec));
    }
    let typed: Vec<(&str, Option<&str>)> = requested
        .iter()
        .map(|a| {
            (
                a.r#type.as_deref().unwrap_or(IP_ADDRESS),
                a.value.as_deref().filter(|v| !v.is_empty()),
            )
        })
        .collect();
    if let Some((t, _)) = typed
        .iter()
        .find(|(t, _)| *t != IP_ADDRESS && *t != HOSTNAME)
    {
        return Err(SpecIssue::UnsupportedAddress((*t).to_string()));
    }
    let published = published.unwrap_or_default();
    let mut out: Vec<(String, String)> = Vec::new();
    for (t, value) in typed {
        let matching: Vec<&(String, String)> = match value {
            Some(v) => published
                .iter()
                .filter(|(pt, pv)| pt == t && same_address(t, pv, v))
                .collect(),
            None => published.iter().filter(|(pt, _)| pt == t).collect(),
        };
        if matching.is_empty() {
            return Err(match value {
                Some(v) => SpecIssue::AddressNotUsable(v.to_string()),
                None => SpecIssue::AddressNotAssigned(t.to_string()),
            });
        }
        for address in matching {
            if !out.contains(address) {
                out.push(address.clone());
            }
        }
    }
    Ok(Some(out))
}

/// Whether two addresses of type `t` are the same: IPs once parsed,
/// hostnames regardless of case.
fn same_address(t: &str, a: &str, b: &str) -> bool {
    if t == IP_ADDRESS {
        match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_api::apis::standard::gateways::{
        GatewayAddresses, GatewayInfrastructure, GatewayInfrastructureParametersRef, GatewaySpec,
    };

    fn gateway(addresses: &[(Option<&str>, Option<&str>)]) -> Gateway {
        let mut gw = Gateway::new(
            "gw",
            GatewaySpec {
                gateway_class_name: "sozune".into(),
                ..Default::default()
            },
        );
        if !addresses.is_empty() {
            gw.spec.addresses = Some(
                addresses
                    .iter()
                    .map(|(t, v)| GatewayAddresses {
                        r#type: t.map(String::from),
                        value: v.map(String::from),
                    })
                    .collect(),
            );
        }
        gw
    }

    fn published() -> Vec<(String, String)> {
        vec![
            (IP_ADDRESS.into(), "192.0.2.10".into()),
            (IP_ADDRESS.into(), "2001:db8::1".into()),
            (HOSTNAME.into(), "lb.example.com".into()),
        ]
    }

    #[test]
    fn a_gateway_without_addresses_gets_every_published_one() {
        let published = published();
        assert_eq!(
            resolve(&gateway(&[]), Some(&published)),
            Ok(Some(published.clone()))
        );
        assert_eq!(resolve(&gateway(&[]), None), Ok(None));
    }

    #[test]
    fn a_gateway_gets_only_the_addresses_it_names() {
        let published = published();
        let gw = gateway(&[
            (None, Some("2001:db8:0::1")),
            (Some(HOSTNAME), Some("LB.example.com")),
        ]);
        assert_eq!(
            resolve(&gw, Some(&published)),
            Ok(Some(vec![
                (IP_ADDRESS.into(), "2001:db8::1".into()),
                (HOSTNAME.into(), "lb.example.com".into()),
            ]))
        );
    }

    #[test]
    fn an_address_without_value_takes_those_of_its_type() {
        let published = published();
        let gw = gateway(&[(Some(IP_ADDRESS), None)]);
        assert_eq!(
            resolve(&gw, Some(&published)),
            Ok(Some(published[..2].to_vec()))
        );
        let only_hostname = vec![(HOSTNAME.to_string(), "lb.example.com".to_string())];
        assert_eq!(
            resolve(&gw, Some(&only_hostname)),
            Err(SpecIssue::AddressNotAssigned(IP_ADDRESS.into()))
        );
    }

    #[test]
    fn an_address_sozune_does_not_publish_is_not_usable() {
        let published = published();
        let gw = gateway(&[(None, Some("192.0.2.10")), (None, Some("198.51.100.1"))]);
        assert_eq!(
            resolve(&gw, Some(&published)),
            Err(SpecIssue::AddressNotUsable("198.51.100.1".into()))
        );
        // Nothing published yet: no address can be served.
        let gw = gateway(&[(None, Some("192.0.2.10"))]);
        assert_eq!(
            resolve(&gw, None),
            Err(SpecIssue::AddressNotUsable("192.0.2.10".into()))
        );
        // Same value, other type.
        let gw = gateway(&[(Some(HOSTNAME), Some("192.0.2.10"))]);
        assert!(resolve(&gw, Some(&published)).is_err());
    }

    #[test]
    fn an_unsupported_address_type_refuses_the_gateway() {
        let published = published();
        let gw = gateway(&[
            (Some("test/fake-invalid-type"), Some("fake")),
            (None, Some("198.51.100.1")),
        ]);
        let issue = resolve(&gw, Some(&published)).unwrap_err();
        assert_eq!(
            issue,
            SpecIssue::UnsupportedAddress("test/fake-invalid-type".into())
        );
        assert!(!issue.accepted());
        assert!(SpecIssue::AddressNotUsable(String::new()).accepted());
    }

    #[test]
    fn infrastructure_parameters_refuse_the_gateway() {
        let published = published();
        let mut gw = gateway(&[]);
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            parameters_ref: Some(GatewayInfrastructureParametersRef {
                group: "invalid.io".into(),
                kind: "InvalidParameters".into(),
                name: "invalid".into(),
            }),
            ..Default::default()
        });
        assert_eq!(
            resolve(&gw, Some(&published)),
            Err(SpecIssue::InvalidParameters)
        );
        // Labels and annotations alone are fine.
        gw.spec.infrastructure = Some(GatewayInfrastructure::default());
        assert_eq!(resolve(&gw, Some(&published)), Ok(Some(published.clone())));
    }
}
