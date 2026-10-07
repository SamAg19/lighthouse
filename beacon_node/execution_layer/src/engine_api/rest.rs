//! Contains an implementation of the Engine API over REST + SSZ (execution-apis#793).

use crate::auth::Auth;
use crate::engine_api::{
    ClientVersionV1, ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT, ENGINE_FORKCHOICE_UPDATED_TIMEOUT,
    ENGINE_GET_BLOBS_TIMEOUT, ENGINE_GET_CLIENT_VERSION_TIMEOUT, ENGINE_GET_PAYLOAD_BODIES_TIMEOUT,
    ENGINE_GET_PAYLOAD_TIMEOUT, ENGINE_NEW_PAYLOAD_TIMEOUT, Error, ExecutionPayloadBodyV1,
    ExecutionPayloadBodyV2, ForkchoiceUpdatedResponse, GetPayloadResponse, NewPayloadRequest,
    PayloadAttributes, PayloadId, PayloadStatusV1, PayloadStatusV1Status,
};
use crate::engines::ForkchoiceState;
use crate::http::{CachedResponse, LIGHTHOUSE_JSON_CLIENT_VERSION};
use crate::json_structures::{
    BlobAndProofV2, BlobAndProofV3, CustodyColumnsBitArray, GetBlobsV4List, JsonClientVersionV1,
};
use crate::ssz_structures::*;
use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Client, Method, StatusCode};
use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use ssz::{Decode, Encode};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::error;
use types::{ColumnIndex, EthSpec, ExecutionBlockHash, ForkName, Hash256};

const BASE: &str = "/engine/v1";
const ETH_EXECUTION_VERSION: &str = "Eth-Execution-Version";
const X_ENGINE_CLIENT_VERSION: &str = "X-Engine-Client-Version";

// SSZ for hot-path bodies/responses, JSON for the diagnostic endpoints.
const OCTET_STREAM: &str = "application/octet-stream";
const APPLICATION_JSON: &str = "application/json";
const H2_CONNECTION_WINDOW: u32 = 1024 * 1024;
const H2_STREAM_WINDOW: u32 = 1024 * 1024;

// The CL's `X-Engine-Client-Version` header value, e.g. `LH/v6.2.1`.
static CLIENT_VERSION_HEADER: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}/{}",
        LIGHTHOUSE_JSON_CLIENT_VERSION.code, LIGHTHOUSE_JSON_CLIENT_VERSION.version
    )
});

#[derive(Debug, Copy, Clone)]
pub enum HttpVersion {
    Http2,
    Http1,
}

impl HttpVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http2 => "http2",
            HttpVersion::Http1 => "http1",
        }
    }
}

#[derive(Deserialize)]
struct JsonProblem {
    #[serde(rename = "type")]
    type_uri: String,
    detail: Option<String>,
}

/// A REST + SSZ Engine API client. Mirrors `HttpJsonRpc`, but speaks `/engine/v1/...` with
/// `application/octet-stream` SSZ bodies and RFC 7807 problem responses.
pub struct HttpRestSsz {
    pub client_h2c: Client,
    pub client_h1: Client,
    pub http_version: OnceLock<HttpVersion>,
    pub url: SensitiveUrl,
    pub execution_timeout_multiplier: u32,
    pub ssz_capabilities_cache: Mutex<Option<CachedResponse<SszCapabilities>>>,
    pub engine_version_cache: Mutex<Option<CachedResponse<Vec<ClientVersionV1>>>>,
    auth: Option<Auth>,
}

impl HttpRestSsz {
    pub fn new(
        url: SensitiveUrl,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        let execution_timeout_multiplier = execution_timeout_multiplier.unwrap_or(1);
        Ok(Self {
            client_h2c: Client::builder()
                .http2_prior_knowledge()
                .http2_initial_stream_window_size(H2_STREAM_WINDOW)
                .http2_initial_connection_window_size(H2_CONNECTION_WINDOW)
                .build()?,
            client_h1: Client::builder().build()?,
            http_version: OnceLock::new(),
            url,
            execution_timeout_multiplier,
            ssz_capabilities_cache: Mutex::new(None),
            engine_version_cache: Mutex::new(None),
            auth: None,
        })
    }

    pub fn new_with_auth(
        url: SensitiveUrl,
        auth: Auth,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        Ok(Self {
            auth: Some(auth),
            ..Self::new(url, execution_timeout_multiplier)?
        })
    }

    fn selected_client(&self) -> &Client {
        match self.http_version.get() {
            None | Some(HttpVersion::Http2) => &self.client_h2c,
            Some(HttpVersion::Http1) => &self.client_h1,
        }
    }

    /// The single REST-SSZ transport chokepoint. `Some(bytes)` on `200`, `None` on `204`.
    pub async fn rest_request(
        &self,
        method: Method,
        path: &str,
        fork: Option<ForkName>,
        body: Option<Vec<u8>>,
        accept: &str,
        timeout: Duration,
    ) -> Result<Option<Bytes>, Error> {
        let client = self.selected_client();
        let url = self
            .url
            .expose_full()
            .join(&format!("{BASE}/{path}"))
            .map_err(|e| Error::RequestFailed(format!("failed to build REST url: {e}")))?;

        let mut request = client
            .request(method, url)
            .timeout(timeout)
            .header(ACCEPT, accept)
            .header(X_ENGINE_CLIENT_VERSION, CLIENT_VERSION_HEADER.as_str());

        if let Some(fork) = fork {
            request = request.header(ETH_EXECUTION_VERSION, fork_to_header(fork)?);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, OCTET_STREAM).body(body);
        }
        if let Some(auth) = &self.auth {
            request = request.bearer_auth(auth.generate_token()?);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(e) if e.status().is_none() && !e.is_timeout() => {
                return Err(Error::TransportUnreachable(e.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        // 401/403 are auth failures, outside the RFC 7807 model — reuse the JSON-RPC `From` mapping.
        if let Err(e) = response.error_for_status_ref()
            && matches!(
                e.status(),
                Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN)
            )
        {
            return Err(e.into());
        }

        match response.status() {
            StatusCode::OK => {
                let bytes = response.bytes().await?;
                Ok(Some(bytes))
            }
            StatusCode::NO_CONTENT => Ok(None),
            status => {
                let (problem, detail) = match response.json::<JsonProblem>().await {
                    Ok(body) => (
                        body.type_uri
                            .rsplit('/')
                            .next()
                            .unwrap_or_default()
                            .to_string(),
                        body.detail,
                    ),
                    Err(_) => (String::new(), None),
                };
                Err(Error::RestProblem {
                    status: status.as_u16(),
                    problem,
                    detail,
                })
            }
        }
    }

    pub async fn get_ssz_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<SszCapabilities, Error> {
        let mut lock = self.ssz_capabilities_cache.lock().await;
        if let Some(cached) = lock.as_ref().filter(|c| !c.older_than(age_limit)) {
            Ok(cached.data())
        } else {
            let capabilities = self.fetch_ssz_capabilities().await?;
            *lock = Some(CachedResponse::new(capabilities.clone()));
            Ok(capabilities)
        }
    }

    pub async fn clear_ssz_capabilities_cache(&self) {
        *self.ssz_capabilities_cache.lock().await = None;
    }

    async fn fetch_ssz_capabilities(&self) -> Result<SszCapabilities, Error> {
        let body = self
            .rest_request(
                Method::GET,
                "capabilities",
                None,
                None,
                APPLICATION_JSON,
                ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /capabilities".to_string()))?;
        let capabilities: JsonCapabilities = serde_json::from_slice(&body)?;
        Ok(capabilities.into())
    }

    pub async fn get_client_version_v1(&self) -> Result<Vec<ClientVersionV1>, Error> {
        let body = self
            .rest_request(
                Method::GET,
                "identity",
                None,
                None,
                APPLICATION_JSON,
                ENGINE_GET_CLIENT_VERSION_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /identity".to_string()))?;
        let versions: Vec<JsonClientVersionV1> = serde_json::from_slice(&body)?;
        versions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::InvalidClientVersion)
    }

    pub async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, Error> {
        if !self
            .get_ssz_capabilities(None)
            .await?
            .get_client_version_v1()
        {
            return Ok(vec![]);
        }
        let mut lock = self.engine_version_cache.lock().await;
        if let Some(cached) = lock.as_ref().filter(|c| !c.older_than(age_limit)) {
            Ok(cached.data())
        } else {
            let versions = self.get_client_version_v1().await?;
            *lock = Some(CachedResponse::new(versions.clone()));
            Ok(versions)
        }
    }

    pub async fn clear_engine_version_cache(&self) {
        *self.engine_version_cache.lock().await = None;
    }

    pub async fn new_payload<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, Error> {
        let (fork, body) = match new_payload_request {
            NewPayloadRequest::Bellatrix(request) => (
                ForkName::Bellatrix,
                SszExecutionPayloadEnvelopeBellatrix::from(request).as_ssz_bytes(),
            ),
            NewPayloadRequest::Capella(request) => (
                ForkName::Capella,
                SszExecutionPayloadEnvelopeCapella::from(request).as_ssz_bytes(),
            ),
            NewPayloadRequest::Deneb(request) => (
                ForkName::Deneb,
                SszExecutionPayloadEnvelopeDeneb::from(request).as_ssz_bytes(),
            ),
            NewPayloadRequest::Electra(request) => (
                ForkName::Electra,
                SszExecutionPayloadEnvelopeElectra::try_from(request)?.as_ssz_bytes(),
            ),
            NewPayloadRequest::Fulu(request) => (
                ForkName::Fulu,
                SszExecutionPayloadEnvelopeFulu::try_from(request)?.as_ssz_bytes(),
            ),
            NewPayloadRequest::Gloas(request) => (
                ForkName::Gloas,
                SszExecutionPayloadEnvelopeGloas::try_from(request)?.as_ssz_bytes(),
            ),
            NewPayloadRequest::Heze(request) => (
                ForkName::Heze,
                SszExecutionPayloadEnvelopeHeze::try_from(request)?.as_ssz_bytes(),
            ),
        };

        let response = self
            .rest_request(
                Method::POST,
                "payloads",
                Some(fork),
                Some(body),
                OCTET_STREAM,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /payloads".to_string()))?;

        let status =
            SszPayloadStatusV1::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        PayloadStatusV1::try_from(status)
    }

    pub async fn forkchoice_updated<E: EthSpec>(
        &self,
        fork: ForkName,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
        custody_columns: Option<&[ColumnIndex]>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let custody_columns = Self::custody_columns_param(custody_columns, fork);

        let body = if fork >= ForkName::Gloas {
            SszForkchoiceUpdateCustodyColumns::<E>::new(
                fork,
                forkchoice_state,
                payload_attributes,
                custody_columns,
            )?
            .as_ssz_bytes()
        } else {
            SszForkchoiceUpdate::new(fork, forkchoice_state, payload_attributes)?.as_ssz_bytes()
        };

        let response = self
            .rest_request(
                Method::POST,
                "forkchoice",
                Some(fork),
                Some(body),
                OCTET_STREAM,
                ENGINE_FORKCHOICE_UPDATED_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /forkchoice".to_string()))?;

        let ssz_response = SszForkchoiceUpdatedResponse::<E>::from_ssz_bytes(&response)
            .map_err(Error::SszDecode)?;
        let response = ForkchoiceUpdatedResponse::try_from(ssz_response)?;

        // `/forkchoice` MUST NOT return ACCEPTED; treat a `3` as a non-conformant EL error.
        if matches!(
            response.payload_status.status,
            PayloadStatusV1Status::Accepted
        ) {
            return Err(Error::BadResponse(
                "forkchoiceUpdated returned ACCEPTED, which is not a valid forkchoice status"
                    .to_string(),
            ));
        }

        Ok(response)
    }

    fn custody_columns_param(
        custody_columns: Option<&[ColumnIndex]>,
        fork: ForkName,
    ) -> Option<CustodyColumnsBitArray> {
        custody_columns
            .map(CustodyColumnsBitArray::try_from)
            .transpose()
            .unwrap_or_else(|err| {
                error!(
                    ?err,
                    %fork, "Failed to convert custody columns for forkchoice update"
                );
                None
            })
    }

    pub async fn get_payload<E: EthSpec>(
        &self,
        fork: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let path = format!("payloads/0x{}", hex::encode(payload_id));
        let response = self
            .rest_request(
                Method::GET,
                &path,
                Some(fork),
                None,
                OCTET_STREAM,
                ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /payloads/{id}".to_string()))?;

        let built_payload = SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(&response, fork)
            .map_err(Error::SszDecode)?;
        GetPayloadResponse::try_from(built_payload)
            .map_err(|e| Error::BadResponse(format!("{e:?}")))
    }

    pub async fn get_blobs_v2<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, Error> {
        let body = SszBlobsRequest::<E>::new_blobs_request_v1(versioned_hashes)?.as_ssz_bytes();
        let Some(response) = self
            .rest_request(
                Method::POST,
                "blobs/v2",
                None,
                Some(body),
                OCTET_STREAM,
                ENGINE_GET_BLOBS_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
        else {
            return Ok(None);
        };
        let response =
            SszBlobsResponseV2::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        Ok(Some(response.into_v2()))
    }

    pub async fn get_blobs_v3<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV3<E>>>, Error> {
        let body = SszBlobsRequest::<E>::new_blobs_request_v1(versioned_hashes)?.as_ssz_bytes();
        let Some(response) = self
            .rest_request(
                Method::POST,
                "blobs/v3",
                None,
                Some(body),
                OCTET_STREAM,
                ENGINE_GET_BLOBS_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
        else {
            return Ok(None);
        };
        let response =
            SszBlobsResponseV2::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        Ok(Some(response.into_v3()))
    }

    pub async fn get_blobs_v4<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
        indices_bitarray: CustodyColumnsBitArray,
    ) -> Result<Option<GetBlobsV4List<E>>, Error> {
        let body = SszBlobsRequest::<E>::new_blobs_request_v2(versioned_hashes, indices_bitarray)?
            .as_ssz_bytes();
        let Some(response) = self
            .rest_request(
                Method::POST,
                "blobs/v4",
                None,
                Some(body),
                OCTET_STREAM,
                ENGINE_GET_BLOBS_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
        else {
            return Ok(None);
        };
        let response =
            SszBlobsResponseV4::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        Ok(Some(response.into_v4()))
    }

    pub async fn get_payload_bodies_by_hash_v1<E: EthSpec>(
        &self,
        fork: ForkName,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, Error> {
        let block_hashes = block_hashes
            .into_iter()
            .map(|hash| hash.into_root())
            .collect();
        let body = SszBodiesByHashRequest::new(block_hashes)?.as_ssz_bytes();
        let response = self
            .rest_request(
                Method::POST,
                "bodies/hash",
                Some(fork),
                Some(body),
                OCTET_STREAM,
                ENGINE_GET_PAYLOAD_BODIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /bodies/hash".to_string()))?;

        SszBodiesResponse::<E>::from_ssz_bytes_by_fork(&response, fork)
            .map_err(Error::SszDecode)?
            .into_bodies()
    }

    pub async fn get_payload_bodies_by_hash_v2<E: EthSpec>(
        &self,
        fork: ForkName,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV2<E>>>, Error> {
        let block_hashes = block_hashes
            .into_iter()
            .map(|hash| hash.into_root())
            .collect();
        let body = SszBodiesByHashRequest::new(block_hashes)?.as_ssz_bytes();
        let response = self
            .rest_request(
                Method::POST,
                "bodies/hash",
                Some(fork),
                Some(body),
                OCTET_STREAM,
                ENGINE_GET_PAYLOAD_BODIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /bodies/hash".to_string()))?;

        SszBodiesResponse::<E>::from_ssz_bytes_by_fork(&response, fork)
            .map_err(Error::SszDecode)?
            .into_bodies_v2()
            .map_err(Error::SszError)
    }
}

fn fork_to_header(fork: ForkName) -> Result<&'static str, Error> {
    Ok(match fork {
        ForkName::Bellatrix => "paris",
        ForkName::Capella => "shanghai",
        ForkName::Deneb => "cancun",
        ForkName::Electra => "prague",
        ForkName::Fulu => "osaka",
        ForkName::Gloas => "amsterdam",
        ForkName::Heze => "bogota",
        ForkName::Base | ForkName::Altair => {
            return Err(Error::UnsupportedForkVariant(format!(
                "no engine-api fork header for {fork}"
            )));
        }
    })
}

pub fn header_to_fork(header: &str) -> Option<ForkName> {
    Some(match header {
        "paris" => ForkName::Bellatrix,
        "shanghai" => ForkName::Capella,
        "cancun" => ForkName::Deneb,
        "prague" => ForkName::Electra,
        "osaka" => ForkName::Fulu,
        "amsterdam" => ForkName::Gloas,
        "bogota" => ForkName::Heze,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_to_header_maps_every_fork() {
        assert_eq!(fork_to_header(ForkName::Bellatrix).unwrap(), "paris");
        assert_eq!(fork_to_header(ForkName::Capella).unwrap(), "shanghai");
        assert_eq!(fork_to_header(ForkName::Deneb).unwrap(), "cancun");
        assert_eq!(fork_to_header(ForkName::Electra).unwrap(), "prague");
        assert_eq!(fork_to_header(ForkName::Fulu).unwrap(), "osaka");
        assert_eq!(fork_to_header(ForkName::Gloas).unwrap(), "amsterdam");
        assert!(fork_to_header(ForkName::Base).is_err());
        assert!(fork_to_header(ForkName::Altair).is_err());
    }

    #[test]
    fn header_to_fork_maps_every_header() {
        assert_eq!(header_to_fork("paris"), Some(ForkName::Bellatrix));
        assert_eq!(header_to_fork("shanghai"), Some(ForkName::Capella));
        assert_eq!(header_to_fork("cancun"), Some(ForkName::Deneb));
        assert_eq!(header_to_fork("prague"), Some(ForkName::Electra));
        assert_eq!(header_to_fork("osaka"), Some(ForkName::Fulu));
        assert_eq!(header_to_fork("amsterdam"), Some(ForkName::Gloas));
        assert_eq!(header_to_fork("frontier"), None);
        assert_eq!(header_to_fork(""), None);
    }

    #[test]
    fn capabilities_parse_full_body() {
        let body = r#"{
            "supported_forks": ["paris","shanghai","cancun","prague","osaka","amsterdam"],
            "fork_scoped_endpoints": ["payloads","forkchoice","bodies"],
            "independently_versioned": { "blobs": ["v1","v2","v3","v4"] },
            "unscoped_endpoints": ["capabilities","identity"],
            "limits": {
                "bodies.max_count": 32,
                "blobs.max_versioned_hashes": 128,
                "payload.max_bytes": 67108864
            }
        }"#;
        let capabilities: SszCapabilities = serde_json::from_str::<JsonCapabilities>(body)
            .unwrap()
            .into();

        for fork in [
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
            ForkName::Gloas,
        ] {
            assert!(capabilities.supported_forks.contains(&fork));
        }
        assert!(capabilities.payloads && capabilities.forkchoice && capabilities.bodies);
        assert!(
            capabilities.blobs_v1
                && capabilities.blobs_v2
                && capabilities.blobs_v3
                && capabilities.blobs_v4
        );
        assert!(capabilities.get_client_version_v1());
        assert_eq!(capabilities.limits.bodies_max_count, Some(32));
        assert_eq!(capabilities.limits.blobs_max_versioned_hashes, Some(128));
        assert_eq!(capabilities.limits.payload_max_bytes, Some(67108864));

        assert!(capabilities.new_payload(ForkName::Gloas));
        assert!(!capabilities.new_payload(ForkName::Base));
        assert_eq!(capabilities.highest_supported_fork(), Some(ForkName::Gloas));
    }

    #[test]
    fn capabilities_ignore_unknowns_and_default_absent_fields() {
        let body = r#"{
            "supported_forks": ["amsterdam","futurefork"],
            "fork_scoped_endpoints": ["payloads"],
            "independently_versioned": { "blobs": [] },
            "unscoped_endpoints": []
        }"#;
        let capabilities: SszCapabilities = serde_json::from_str::<JsonCapabilities>(body)
            .unwrap()
            .into();

        // Unrecognised forks are dropped rather than rejected.
        assert!(capabilities.supported_forks.contains(&ForkName::Gloas));
        assert_eq!(capabilities.supported_forks.len(), 1);
        assert!(capabilities.payloads && !capabilities.forkchoice && !capabilities.bodies);
        assert!(!capabilities.blobs_v2);
        assert!(!capabilities.get_client_version_v1());
        assert_eq!(capabilities.limits.payload_max_bytes, None);
    }

    #[test]
    fn problem_body_parses_with_and_without_detail() {
        let with_detail = r#"{"type":"/engine-api/errors/unknown-payload","detail":"no such id"}"#;
        let problem: JsonProblem = serde_json::from_str(with_detail).unwrap();
        assert_eq!(problem.type_uri, "/engine-api/errors/unknown-payload");
        assert_eq!(problem.detail.as_deref(), Some("no such id"));

        let canned = r#"{"type":"/engine-api/errors/ssz-decode-error"}"#;
        let problem: JsonProblem = serde_json::from_str(canned).unwrap();
        assert_eq!(problem.detail, None);
    }
}
