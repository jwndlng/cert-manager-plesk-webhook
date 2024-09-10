use anyhow::{Error, anyhow};
use std::io;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use tracing::info;
use serde_xml_rs::from_str;

const PLESK_API_PATH: &str = "/enterprise/control/agent.php";
const ACME_CHALLENGE_PREFIX: &str = "_acme-challenge";

#[derive(Clone)]
pub struct PleskAPI {
    url: String,
    client: Client,
    site_id: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponse {
    dns: PleskDNSResponseDNS,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseDNS {
    add_rec: Option<PleskDNSResponseAction>,
    del_rec: Option<PleskDNSResponseAction>,
    get_rec: Option<PleskDNSResponseActions>
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseAction {
    result: PleskDNSResponseResult,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseActions {
    result: Vec<PleskDNSResponseResult>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseResult {
    status: String,
    errcode: Option<String>,
    errtext: Option<String>,
    id: Option<String>,
    data: Option<PleskDNSResponseData>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseData {
    #[serde(rename = "site-id")]
    pub site_id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub host: String,
    pub value: String,
    pub opt: Option<String>,
}

impl PleskAPI {
    pub fn new(url: String, site_id: String, username: String, password: String) -> Self {
        Self {
            url,
            client: Client::new(),
            site_id,
            username,
            password,
        }
    }

    fn get_api_url(&self) -> String {
        format!("{}{}", self.url, PLESK_API_PATH)
    }

    fn create_request(&self) -> RequestBuilder {
        self.client
            .post(self.get_api_url())
            .header("Content-Type", "text/xml")
            .header("HTTP_AUTH_LOGIN", self.username.clone())
            .header("HTTP_AUTH_PASSWD", self.password.clone())
    }

    pub async fn add_challenge(&self, challenge_string: String) -> Result<String, Error> {
        let payload = format!(
            r#"
                <packet>
                    <dns>
                        <add_rec>
                            <site-id>{}</site-id>
                            <type>TXT</type>
                            <host>{}</host>
                            <value>{}</value>
                        </add_rec>
                    </dns>
                </packet>
            "#,
            self.site_id,
            ACME_CHALLENGE_PREFIX,
            challenge_string
        );
        let response = self
            .create_request()
            .body(payload)
            .send()
            .await?;

        let response_text = response.text().await?;

        let dns_response: PleskDNSResponse = match from_str(&response_text) {
            Ok(response) => response,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };

        if let Some(dns_resp_record) = dns_response.dns.add_rec {
            if dns_resp_record.result.status == "error" {
                let error_msg = dns_resp_record.result.errtext.unwrap();
                if error_msg.contains("exists") {
                    info!("Record already exists, retrieving record ID");
                    let record_id = self.get_challenge_record_id().await?;
                    return Ok(record_id);
                } else {
                    let error = io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Plesk API error: {}",
                            error_msg
                        ),
                    );
                    return Err(anyhow!(error));
                }
            }
            let record_id = dns_resp_record.result.id.unwrap();
            return Ok(record_id);
        }
        let error = io::Error::new(
            io::ErrorKind::Other,
            format!("Response could not be parsed: {}", response_text),
        );
        Err(anyhow!(error))
    }


    pub async fn remove_challenge(&self, record_id: String) -> Result<String, Error> {
        let response = self
            .create_request()
            .body(format!(
                r#"
                    <packet>
                        <dns>
                            <del_rec>
                                <filter>
                                    <id>{}</id>
                                </filter>
                            </del_rec>
                        </dns>
                    </packet>
                "#,
                record_id
                )
            )
            .send()
            .await?;

        let response_text = response.text().await?;

        let dns_response: PleskDNSResponse = match from_str(&response_text) {
            Ok(response) => response,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };

        if let Some(dns_resp_record) = dns_response.dns.del_rec {
            if dns_resp_record.result.status == "error" {
                let error = io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Plesk API error: {}",
                        dns_resp_record.result.errtext.unwrap()
                    ),
                );
                return Err(anyhow!(error));
            }
            return Ok(record_id);
        }

        let error = io::Error::new(
            io::ErrorKind::Other,
            format!("Response could not be parsed: {}", response_text),
        );
        Err(anyhow!(error))
    }

    pub async fn get_challenge_record_id(&self) -> Result<String, Error> {
        info!("Getting challenge record ID");
        let response = self
            .create_request()
            .body(format!(
                r#"
                    <packet>
                        <dns>
                            <get_rec>
                                <filter>
                                    <site-id>{}</site-id>
                                </filter>
                            </get_rec>
                        </dns>
                    </packet>
                "#,
                self.site_id
                )
            )
            .send()
            .await?;

        let response_text = response.text().await?;
        let dns_response: PleskDNSResponse = match from_str(&response_text) {
            Ok(response) => response,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };

        if let Some(dns_resp_record) = dns_response.dns.get_rec {
            let actions = dns_resp_record.result;
            for action in actions {
                if action.data.is_none() {
                    continue;
                }
                let record_data = action.data.unwrap();
                if record_data.host.contains(ACME_CHALLENGE_PREFIX) {
                    info!("Found record ID: {}", action.id.clone().unwrap());
                    return Ok(action.id.unwrap());
                }
            }
        }
        Err(anyhow!("No record found"))
    }

}