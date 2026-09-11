use std::{
    collections::{HashMap, HashSet},
    env, fs,
    sync::Arc,
    time::Duration as StdDuration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::{sync::RwLock, task, time::sleep};
use tracing::{error, info, warn};
use url::Url;

const POSTGRES_ADMIN_URL_ENV: &str = "SECRET_BROKER_POSTGRES_ADMIN_URL";
const POSTGRES_POOL_MAX_ENV: &str = "SECRET_BROKER_POSTGRES_POOL_MAX";
const POSTGRES_DEFAULT_ROLES_ENV: &str = "SECRET_BROKER_POSTGRES_DEFAULT_ROLES";
const POSTGRES_AUDIENCE_URLS_ENV: &str = "SECRET_BROKER_POSTGRES_AUDIENCE_URLS";
const POSTGRES_AUDIENCE_ROLES_ENV: &str = "SECRET_BROKER_POSTGRES_AUDIENCE_ROLES";
const POSTGRES_CA_CERT_ENV: &str = "SECRET_BROKER_POSTGRES_CA_CERT";
const POSTGRES_CA_CERT_PATH_ENV: &str = "SECRET_BROKER_POSTGRES_CA_CERT_PATH";
const POSTGRES_SERVER_FINGERPRINT_ENV: &str = "SECRET_BROKER_POSTGRES_SERVER_FINGERPRINT";
const POSTGRES_DEFAULT_TTL_ENV: &str = "SECRET_BROKER_POSTGRES_DEFAULT_TTL_SECS";
const POSTGRES_MAX_TTL_ENV: &str = "SECRET_BROKER_POSTGRES_MAX_TTL_SECS";
const POSTGRES_CLEANUP_INTERVAL_ENV: &str = "SECRET_BROKER_POSTGRES_CLEANUP_INTERVAL_SECS";
const LEASE_USAGE_SCHEMAS: &[&str] = &["gateway_secrets", "gateway_data", "database_extensions"];
const LEASE_RW_SCHEMAS: &[&str] = &["gateway_secrets", "gateway_data"];

#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub database_url: String,
    pub username: String,
    pub password: String,
    pub expires_at: DateTime<Utc>,
    pub ca_certificate_pem: Option<String>,
    pub server_cert_fingerprint: Option<String>,
}

struct RoleProvisioning<'a> {
    username: &'a str,
    password: &'a str,
    valid_until: &'a DateTime<Utc>,
    target_url: &'a Url,
    audience: &'a str,
    scopes: &'a [String],
    application_name: Option<&'a str>,
}

#[derive(Debug, Clone)]
struct BrokerDatabaseConfig {
    admin_url: String,
    pool_max_connections: u32,
    default_roles: Vec<String>,
    audience_urls: HashMap<String, String>,
    audience_roles: HashMap<String, Vec<String>>,
    ca_certificate_pem: Option<String>,
    server_cert_fingerprint: Option<String>,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    cleanup_interval_seconds: u64,
}

impl BrokerDatabaseConfig {
    fn from_env(max_handle_ttl: Duration) -> Result<Option<Self>> {
        let admin_url = match env::var(POSTGRES_ADMIN_URL_ENV) {
            Ok(url) if !url.trim().is_empty() => url,
            _ => return Ok(None),
        };

        let pool_max_connections = env::var(POSTGRES_POOL_MAX_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5);

        let default_roles = parse_comma_separated(env::var(POSTGRES_DEFAULT_ROLES_ENV).ok());
        let audience_urls = parse_key_value_map(env::var(POSTGRES_AUDIENCE_URLS_ENV).ok());
        let audience_roles = parse_key_value_list_map(env::var(POSTGRES_AUDIENCE_ROLES_ENV).ok());

        let ca_certificate_pem = match (
            env::var(POSTGRES_CA_CERT_ENV).ok(),
            env::var(POSTGRES_CA_CERT_PATH_ENV).ok(),
        ) {
            (Some(inline), _) if !inline.trim().is_empty() => Some(inline),
            (_, Some(path)) if !path.trim().is_empty() => {
                let pem = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read CA bundle at {path}"))?;
                Some(pem)
            }
            _ => None,
        };

        let server_cert_fingerprint =
            env::var(POSTGRES_SERVER_FINGERPRINT_ENV)
                .ok()
                .and_then(|value| {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                });

        let default_ttl_seconds = env::var(POSTGRES_DEFAULT_TTL_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(900);

        let configured_max_ttl = env::var(POSTGRES_MAX_TTL_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or_else(|| max_handle_ttl.num_seconds() as u64);

        let max_ttl_seconds = configured_max_ttl.min(max_handle_ttl.num_seconds() as u64);

        let cleanup_interval_seconds = env::var(POSTGRES_CLEANUP_INTERVAL_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(300);

        Ok(Some(Self {
            admin_url,
            pool_max_connections,
            default_roles,
            audience_urls,
            audience_roles,
            ca_certificate_pem,
            server_cert_fingerprint,
            default_ttl_seconds,
            max_ttl_seconds,
            cleanup_interval_seconds,
        }))
    }
}

pub struct PostgresLeaseManager {
    inner: Arc<PostgresLeaseManagerInner>,
}

struct PostgresLeaseManagerInner {
    pool: PgPool,
    base_url: Url,
    default_roles: Vec<String>,
    audience_urls: HashMap<String, Url>,
    audience_roles: HashMap<String, Vec<String>>,
    ca_certificate_pem: Option<String>,
    server_cert_fingerprint: Option<String>,
    default_ttl: Duration,
    max_ttl: Duration,
    cleanup_interval: StdDuration,
    issued: RwLock<HashMap<String, DateTime<Utc>>>,
}

impl PostgresLeaseManager {
    pub async fn from_env(max_handle_ttl: Duration) -> Result<Option<Self>> {
        let Some(config) = BrokerDatabaseConfig::from_env(max_handle_ttl)? else {
            return Ok(None);
        };
        Self::new(config).await.map(Some)
    }

    async fn new(config: BrokerDatabaseConfig) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.pool_max_connections)
            .connect(&config.admin_url)
            .await?;

        let base_url = Url::parse(&config.admin_url)?;

        let mut audience_urls = HashMap::new();
        for (audience, url) in config.audience_urls.iter() {
            let parsed = Url::parse(url).with_context(|| {
                format!(
                    "failed to parse audience override URL for audience '{}'",
                    audience
                )
            })?;
            audience_urls.insert(audience.clone(), parsed);
        }

        let default_ttl = Duration::seconds(config.default_ttl_seconds as i64);
        let max_ttl = Duration::seconds(config.max_ttl_seconds as i64);
        let cleanup_interval = StdDuration::from_secs(config.cleanup_interval_seconds);

        let inner = Arc::new(PostgresLeaseManagerInner {
            pool,
            base_url,
            default_roles: config.default_roles,
            audience_urls,
            audience_roles: config.audience_roles,
            ca_certificate_pem: config.ca_certificate_pem,
            server_cert_fingerprint: config.server_cert_fingerprint,
            default_ttl,
            max_ttl,
            cleanup_interval,
            issued: RwLock::new(HashMap::new()),
        });

        let cleanup_inner = Arc::clone(&inner);
        task::spawn(async move {
            Self::cleanup_task(cleanup_inner).await;
        });

        Ok(Self { inner })
    }

    pub async fn issue_credentials(
        &self,
        audience: &str,
        scopes: &[String],
        requested_ttl: Option<u64>,
        exporter_binding: &[u8],
        application_name: Option<&str>,
    ) -> Result<IssuedCredential> {
        if exporter_binding.iter().all(|byte| *byte == 0) {
            anyhow::bail!("exporter binding is required for credential issuance");
        }

        let ttl = self.compute_ttl(requested_ttl)?;
        let expires_at = Utc::now() + ttl;

        let target_url = self
            .inner
            .audience_urls
            .get(audience)
            .cloned()
            .unwrap_or_else(|| self.inner.base_url.clone());

        let username = self.generate_username(audience);
        let password = self.generate_password();

        self.create_role(RoleProvisioning {
            username: &username,
            password: &password,
            valid_until: &expires_at,
            target_url: &target_url,
            audience,
            scopes,
            application_name,
        })
        .await?;

        let mut lease_url = target_url;
        lease_url
            .set_username(&username)
            .map_err(|_| anyhow::anyhow!("failed to set username on lease URL"))?;
        lease_url
            .set_password(Some(&password))
            .map_err(|_| anyhow::anyhow!("failed to set password on lease URL"))?;

        if let Some(app_name) = application_name.and_then(sanitize_application_name) {
            lease_url
                .query_pairs_mut()
                .append_pair("application_name", &app_name);
        }

        {
            let mut issued = self.inner.issued.write().await;
            issued.insert(username.clone(), expires_at);
        }

        Ok(IssuedCredential {
            database_url: lease_url.to_string(),
            username,
            password,
            expires_at,
            ca_certificate_pem: self.inner.ca_certificate_pem.clone(),
            server_cert_fingerprint: self.inner.server_cert_fingerprint.clone(),
        })
    }

    fn compute_ttl(&self, requested_ttl: Option<u64>) -> Result<Duration> {
        let requested = requested_ttl.unwrap_or(self.inner.default_ttl.num_seconds() as u64);
        if requested == 0 {
            anyhow::bail!("requested TTL must be greater than zero");
        }

        let ttl = requested.min(self.inner.max_ttl.num_seconds() as u64);
        if ttl == 0 {
            anyhow::bail!("TTL calculation underflowed");
        }

        Ok(Duration::seconds(ttl as i64))
    }

    fn generate_username(&self, audience: &str) -> String {
        let sanitized = sanitize_identifier(audience).unwrap_or_else(|| "lease".to_string());
        let random: String = hex::encode(OsRng.gen::<[u8; 8]>());
        let mut username = format!("{}_{}", sanitized, &random[..16]);
        if username.len() > 63 {
            let overflow = username.len() - 63;
            let trimmed = sanitized
                .chars()
                .take(sanitized.len().saturating_sub(overflow))
                .collect::<String>();
            username = format!("{}_{}", trimmed, &random[..16]);
        }
        username
    }

    fn generate_password(&self) -> String {
        OsRng
            .sample_iter(&Alphanumeric)
            .map(char::from)
            .take(48)
            .collect()
    }

    async fn create_role(&self, request: RoleProvisioning<'_>) -> Result<()> {
        let mut tx = self.inner.pool.begin().await?;
        let create_sql = format!(
            "CREATE ROLE {} WITH LOGIN PASSWORD {} VALID UNTIL {}",
            quote_identifier(request.username),
            quote_literal(request.password),
            quote_literal(&request.valid_until.to_rfc3339()),
        );
        sqlx::query(&create_sql).execute(&mut *tx).await?;

        if let Some(db_name) = database_name_from_url(request.target_url) {
            let grant_connect = format!(
                "GRANT CONNECT ON DATABASE {} TO {}",
                quote_identifier(&db_name),
                quote_identifier(request.username)
            );
            sqlx::query(&grant_connect).execute(&mut *tx).await?;
        }

        for grant_sql in runtime_schema_grant_statements(request.username) {
            sqlx::query(&grant_sql).execute(&mut *tx).await?;
        }

        let mut roles: HashSet<String> = self.inner.default_roles.iter().cloned().collect();
        if let Some(audience_roles) = self.inner.audience_roles.get(request.audience) {
            roles.extend(audience_roles.iter().cloned());
        }
        for scope in request.scopes {
            roles.insert(scope.clone());
        }

        for role in roles {
            let grant_sql = format!(
                "GRANT {} TO {}",
                quote_identifier(&role),
                quote_identifier(request.username)
            );
            if let Err(err) = sqlx::query(&grant_sql).execute(&mut *tx).await {
                warn!(
                    "failed to grant role '{}' to '{}': {}",
                    role, request.username, err
                );
            }
        }

        if let Some(app_name) = request.application_name.and_then(sanitize_application_name) {
            let alter_sql = format!(
                "ALTER ROLE {} SET application_name = {}",
                quote_identifier(request.username),
                quote_literal(&app_name)
            );
            sqlx::query(&alter_sql).execute(&mut *tx).await?;
        }

        tx.commit().await?;
        info!(
            "issued Postgres lease for audience '{}': {}",
            request.audience, request.username
        );
        Ok(())
    }

    async fn cleanup_task(inner: Arc<PostgresLeaseManagerInner>) {
        loop {
            sleep(inner.cleanup_interval).await;
            if let Err(err) = inner.cleanup_expired_leases().await {
                warn!("postgres lease cleanup encountered error: {}", err);
            }
        }
    }
}

impl PostgresLeaseManagerInner {
    async fn cleanup_expired_leases(&self) -> Result<()> {
        let now = Utc::now();
        let mut expired_users = Vec::new();
        {
            let issued = self.issued.read().await;
            for (username, expiry) in issued.iter() {
                if *expiry + Duration::seconds(60) < now {
                    expired_users.push(username.clone());
                }
            }
        }

        if expired_users.is_empty() {
            return Ok(());
        }

        for username in expired_users.iter() {
            let drop_sql = format!("DROP ROLE IF EXISTS {}", quote_identifier(username));
            match sqlx::query(&drop_sql).execute(&self.pool).await {
                Ok(_) => info!("dropped expired Postgres lease role '{}'", username),
                Err(err) => error!("failed to drop expired role '{}': {}", username, err),
            }
        }

        let mut issued = self.issued.write().await;
        for username in expired_users {
            issued.remove(&username);
        }

        Ok(())
    }
}

fn database_name_from_url(url: &Url) -> Option<String> {
    let path = url.path().trim_start_matches('/');
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn quote_identifier(input: &str) -> String {
    format!("\"{}\"", input.replace('"', "\"\""))
}

fn quote_literal(input: &str) -> String {
    format!("'{}'", input.replace('\'', "''"))
}

fn runtime_schema_grant_statements(username: &str) -> Vec<String> {
    let lease_role = quote_identifier(username);
    let mut statements = Vec::new();

    for schema in LEASE_USAGE_SCHEMAS {
        statements.push(format!(
            "GRANT USAGE ON SCHEMA {} TO {}",
            quote_identifier(schema),
            lease_role
        ));
    }

    for schema in LEASE_RW_SCHEMAS {
        let schema_name = quote_identifier(schema);
        statements.push(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}",
            schema_name, lease_role
        ));
        statements.push(format!(
            "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {} TO {}",
            schema_name, lease_role
        ));
    }

    statements
}

fn sanitize_identifier(audience: &str) -> Option<String> {
    let sanitized: String = audience
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized.to_lowercase())
    }
}

fn sanitize_application_name(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut sanitized = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '/'))
        .collect::<String>();

    if sanitized.is_empty() {
        return None;
    }

    if sanitized.len() > 63 {
        sanitized.truncate(63);
    }

    Some(sanitized)
}

fn parse_comma_separated(input: Option<String>) -> Vec<String> {
    input
        .map(|raw| {
            raw.split(',')
                .filter_map(|item| {
                    let trimmed = item.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_key_value_map(input: Option<String>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(raw) = input {
        for entry in raw.split(';') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                let key_trimmed = key.trim();
                let value_trimmed = value.trim();
                if !key_trimmed.is_empty() && !value_trimmed.is_empty() {
                    map.insert(key_trimmed.to_string(), value_trimmed.to_string());
                }
            }
        }
    }
    map
}

fn parse_key_value_list_map(input: Option<String>) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    if let Some(raw) = input {
        for entry in raw.split(';') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, '=');
            if let (Some(key), Some(values)) = (parts.next(), parts.next()) {
                let roles = values
                    .split(',')
                    .filter_map(|value| {
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    })
                    .collect::<Vec<_>>();
                if !key.trim().is_empty() && !roles.is_empty() {
                    map.insert(key.trim().to_string(), roles);
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::{
        quote_identifier, quote_literal, runtime_schema_grant_statements, sanitize_application_name,
    };

    #[test]
    fn quote_identifier_escapes_double_quotes() {
        assert_eq!(quote_identifier("tenant\"role"), "\"tenant\"\"role\"");
    }

    #[test]
    fn quote_literal_escapes_single_quotes() {
        assert_eq!(quote_literal("pa'ss"), "'pa''ss'");
    }

    #[test]
    fn sanitize_application_name_trims_and_caps_length() {
        let input = "  compose verify / prod-path ........................................  ";
        let sanitized = sanitize_application_name(input).expect("application name");
        assert!(sanitized.len() <= 63);
        assert!(!sanitized.starts_with(' '));
    }

    #[test]
    fn runtime_schema_grants_cover_secret_schema_for_lease_role() {
        let statements = runtime_schema_grant_statements("tenant\"role");
        assert!(statements.iter().any(|statement| {
            statement == "GRANT USAGE ON SCHEMA \"gateway_secrets\" TO \"tenant\"\"role\""
        }));
        assert!(statements.iter().any(|statement| {
            statement
                == "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA \"gateway_secrets\" TO \"tenant\"\"role\""
        }));
        assert!(statements.iter().any(|statement| {
            statement
                == "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA \"gateway_secrets\" TO \"tenant\"\"role\""
        }));
    }
}
