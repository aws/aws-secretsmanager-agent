use std::borrow::Borrow;

use url::Url;

use crate::error::HttpError;

#[derive(Debug)]
pub(crate) struct GSVQuery {
    pub secret_id: String,
    pub version_id: Option<String>,
    pub version_stage: Option<String>,
    pub refresh_now: bool,
}

impl GSVQuery {
    fn parse_refresh_value(s: &str) -> Result<bool, HttpError> {
        match s.to_lowercase().as_str() {
            "true" => Ok(true),
            "1" => Ok(true),
            "false" => Ok(false),
            "0" => Ok(false),
            _ => Err(HttpError(400, "invalid refreshNow value".to_string())),
        }
    }

    pub(crate) fn try_from_query(s: &str) -> Result<Self, HttpError> {
        // url library can only parse complete URIs. The host/port/scheme used is irrelevant since it is not used
        let complete_uri = format!("http://localhost{}", s);

        let url = Url::parse(&complete_uri)?;

        let mut query = GSVQuery {
            secret_id: "".into(),
            version_id: None,
            version_stage: None,
            refresh_now: false,
        };

        for (k, v) in url.query_pairs() {
            match k.borrow() {
                "secretId" => query.secret_id = v.into(),
                "versionId" => query.version_id = Some(v.into()),
                "versionStage" => query.version_stage = Some(v.into()),
                "refreshNow" => query.refresh_now = GSVQuery::parse_refresh_value(&v)?,
                p => return Err(HttpError(400, format!("unknown parameter: {}", p))),
            }
        }

        if query.secret_id.is_empty() {
            return Err(HttpError(400, "missing parameter secretId".to_string()));
        }

        Ok(query)
    }

    pub(crate) fn try_from_path_query(s: &str, path_prefix: &str) -> Result<Self, HttpError> {
        // url library can only parse complete URIs. The host/port/scheme used is irrelevant since it gets stripped
        let complete_uri = format!("http://localhost{}", s);

        let url = Url::parse(&complete_uri)?;

        let secret_id = match url.path().get(path_prefix.len()..) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Err(HttpError(400, "missing secret ID".to_string())),
        };

        let mut query = GSVQuery {
            secret_id,
            version_id: None,
            version_stage: None,
            refresh_now: false,
        };

        for (k, v) in url.query_pairs() {
            match k.borrow() {
                "versionId" => query.version_id = Some(v.into()),
                "versionStage" => query.version_stage = Some(v.into()),
                "refreshNow" => query.refresh_now = GSVQuery::parse_refresh_value(&v)?,
                p => return Err(HttpError(400, format!("unknown parameter: {}", p))),
            }
        }

        Ok(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query() {
        let secret_id = "MyTest".to_owned();
        let query =
            GSVQuery::try_from_query(&format!("/secretsmanager/get?secretId={}", secret_id))
                .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert!(!query.refresh_now);
    }

    #[test]
    fn parse_query_refresh() {
        let secret_id = "MyTest".to_owned();
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&refreshNow={}",
            secret_id, true
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert!(query.refresh_now);
    }

    #[test]
    fn parse_query_refresh_false() {
        let secret_id = "MyTest".to_owned();
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&refreshNow={}",
            secret_id, "0"
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert!(!query.refresh_now);
    }

    #[test]
    fn parse_refresh_invalid_parameter() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&versionId={}&versionStage={}&refreshNow=123",
            secret_id, version_id, version_stage
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "invalid refreshNow value");
            }
        }
    }

    #[test]
    fn parse_refresh_case_insensitive() {
        let secret_id = "MyTest".to_owned();
        let query = GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&refreshNow={}",
            secret_id, "FALSE"
        ))
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, None);
        assert_eq!(query.version_stage, None);
        assert!(!query.refresh_now);
    }

    #[test]
    fn parse_path_query() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        let path_prefix = "/v1/";

        let query = GSVQuery::try_from_path_query(
            &format!(
                "{}{}?versionId={}&versionStage={}",
                path_prefix, secret_id, version_id, version_stage
            ),
            path_prefix,
        )
        .unwrap();

        assert_eq!(query.secret_id, secret_id);
        assert_eq!(query.version_id, Some(version_id));
        assert_eq!(query.version_stage, Some(version_stage));
    }

    #[test]
    fn parse_query_invalid_parameter() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?secretId={}&versionId={}&versionStage={}&abc=123",
            secret_id, version_id, version_stage
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "unknown parameter: abc");
            }
        }
    }

    #[test]
    fn parse_query_path_invalid_parameter() {
        let secret_id = "MyTest".to_owned();
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        let path_prefix = "/v1/";

        match GSVQuery::try_from_path_query(
            &format!(
                "{}{}?versionId={}&versionStage={}&abc=123",
                path_prefix, secret_id, version_id, version_stage
            ),
            path_prefix,
        ) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "unknown parameter: abc");
            }
        }
    }

    #[test]
    fn parse_query_missing_secret_id() {
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        match GSVQuery::try_from_query(&format!(
            "/secretsmanager/get?&versionId={}&versionStage={}",
            version_id, version_stage
        )) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "missing parameter secretId");
            }
        }
    }

    #[test]
    fn parse_query_path_missing_secret_id() {
        let version_id = "myversion".to_owned();
        let version_stage = "dev".to_owned();
        let path_prefix = "/v1/";

        match GSVQuery::try_from_path_query(
            &format!(
                "{}?versionId={}&versionStage={}&abc=123",
                path_prefix, version_id, version_stage
            ),
            path_prefix,
        ) {
            Ok(_) => panic!("should not parse"),
            Err(e) => {
                assert_eq!(e.0, 400);
                assert_eq!(e.1, "missing secret ID");
            }
        }
    }
}
