// TODO: Change some of this to use https://github.com/Azure/azure-sdk-for-rust
// once the api have been stabilized

use crate::http_client::HttpClient;
use crate::http_client::HttpRequestError;
use base64::{self, encode_config};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use ureq::AgentBuilder;

// Types from: https://docs.microsoft.com/en-us/rest/api/attestation/attestation/attestsgxenclave#definitions

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct QuoteRuntimeData {
    data: String,
    #[serde(rename = "dataType")]
    data_type: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct AttestSgxEnclaveRequest {
    quote: String,
    #[serde(rename = "runtimeData")]
    runtime_data: QuoteRuntimeData,
}

impl AttestSgxEnclaveRequest {
    pub(crate) fn from_quote(quote_vec: &Vec<u8>, runtime_data: impl AsRef<[u8]>) -> Self {
        AttestSgxEnclaveRequest {
            quote: encode_config(quote_vec, base64::URL_SAFE),
            runtime_data: QuoteRuntimeData {
                data: encode_config(runtime_data, base64::URL_SAFE),
                data_type: "Binary".to_string(),
            },
        }
    }
}

pub(crate) struct AzureAttestationClient<T: HttpClient + Sized>(T);

impl<T: HttpClient + Sized> AzureAttestationClient<T> {
    /// Creates a new AzureAttestationClient using a ureq Agent
    fn new_ureq() -> AzureAttestationClient<ureq::Agent>
    where
        Self: Sized,
    {
        let agent = AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .build();

        AzureAttestationClient(agent)
    }

    fn attest(
        &self,
        body: AttestSgxEnclaveRequest,
        instance_url: String,
    ) -> Result<AttestationResponse, HttpRequestError> {
        // "https://sharedeus.eus.attest.azure.net"
        let uri = format!("{}/attest/SgxEnclave?api-version=2020-10-01", instance_url);
        self.0.post_json(uri, body)
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct AttestationResponse {
    token: String,
}

#[cfg(test)]
mod test {
    use crate::http_client::MockHttpClient;
    use base64::decode_config;

    use super::*;

    #[test]
    fn from_quote_works() {
        let quote_vec: Vec<u8> = vec![0, 0, 1, 0, 32];
        let runtime_data = b"some runtime data";

        let result = AttestSgxEnclaveRequest::from_quote(&quote_vec, &runtime_data);

        assert_eq!(
            decode_config(result.quote, base64::URL_SAFE).unwrap(),
            quote_vec
        );
        assert_eq!(
            decode_config(result.runtime_data.data, base64::URL_SAFE).unwrap(),
            runtime_data
        );
    }

    #[test]
    fn attest_works() {
        let quote_vec: Vec<u8> = vec![0, 0, 1, 0, 32];
        let runtime_data = b"some runtime data";
        let body = AttestSgxEnclaveRequest::from_quote(&quote_vec, &runtime_data);
        // TODO: Refactor this clone. There is probably a better way
        let body_clone = body.clone();
        let instance_url: &'static str = "https://sharedeus.eus.attest.azure.net";

        let mut mock_client = MockHttpClient::new();
        mock_client
            .expect_post_json()
            .withf(move |uri, b: &AttestSgxEnclaveRequest| {
                *b == body_clone && uri.contains(&instance_url)
            })
            .returning(|_, _| {
                Ok(AttestationResponse {
                    token: "test-token".to_string(),
                })
            });

        let aa_client = AzureAttestationClient(mock_client);

        let result = aa_client.attest(body, instance_url.to_string());

        assert!(result.is_ok());
    }
}
