use anyhow::{Error, anyhow};
use std::io;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
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
    dns: PleskDNSResponseAction,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseAction {
    add_rec: Option<PleskDNSResponseResult>,
    del_rec: Option<PleskDNSResponseResult>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseResult {
    result: PleskDNSResponseData,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PleskDNSResponseData {
    status: String,
    errcode: Option<String>,
    errtext: Option<String>,
    id: Option<String>,
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
                let error = io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Plesk API error: {}",
                        dns_resp_record.result.errtext.unwrap()
                    ),
                );
                return Err(anyhow!(error));
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


    pub async fn remove_challenge(&self, record_id: String) -> Result<(), Error> {
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
            return Ok(());
        }

        let error = io::Error::new(
            io::ErrorKind::Other,
            format!("Response could not be parsed: {}", response_text),
        );
        Err(anyhow!(error))
    }

}