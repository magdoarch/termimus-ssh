//! Docker containers on an SSH host, through the `docker` CLI over exec on
//! the host's connection. When the login user may not use the Docker socket,
//! `sudo -n docker` is tried (works with passwordless sudo).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ssh::SshConnection;

const DOCKER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub command: String,
    /// running, exited, paused, created, restarting, dead
    pub state: String,
    /// "Up 2 days (healthy)", "Exited (0) 3 hours ago"
    pub status: String,
    pub ports: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerStats {
    pub id: String,
    pub cpu_percent: String,
    pub mem_usage: String,
    pub mem_percent: String,
    pub net_io: String,
    pub block_io: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerList {
    pub containers: Vec<Container>,
    /// Docker needed `sudo -n` on this host (for `docker exec` tabs, too).
    pub sudo: bool,
}

/// One line of `docker ps --format '{{json .}}'`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", default)]
#[derive(Default)]
struct PsLine {
    #[serde(rename = "ID")]
    id: String,
    names: String,
    image: String,
    command: String,
    state: String,
    status: String,
    ports: String,
    created_at: String,
}

/// One line of `docker stats --format '{{json .}}'`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct StatsLine {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "CPUPerc")]
    cpu_percent: String,
    #[serde(rename = "MemUsage")]
    mem_usage: String,
    #[serde(rename = "MemPerc")]
    mem_percent: String,
    #[serde(rename = "NetIO")]
    net_io: String,
    #[serde(rename = "BlockIO")]
    block_io: String,
}

fn parse_ps(output: &str) -> Vec<Container> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<PsLine>(line.trim()).ok())
        .filter(|line| !line.id.is_empty())
        .map(|line| {
            // Old Docker versions have no State: derive it from Status.
            let state = if line.state.is_empty() {
                let status = line.status.to_lowercase();
                if status.starts_with("up") && status.contains("paused") {
                    "paused"
                } else if status.starts_with("up") {
                    "running"
                } else if status.starts_with("created") {
                    "created"
                } else {
                    "exited"
                }
                .to_string()
            } else {
                line.state
            };
            Container {
                id: line.id,
                name: line.names,
                image: line.image,
                command: line.command,
                state,
                status: line.status,
                ports: line.ports,
                created_at: line.created_at,
            }
        })
        .collect()
}

fn parse_stats(output: &str) -> Vec<ContainerStats> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<StatsLine>(line.trim()).ok())
        .filter(|line| !line.id.is_empty())
        .map(|line| ContainerStats {
            id: line.id,
            cpu_percent: line.cpu_percent,
            mem_usage: line.mem_usage,
            mem_percent: line.mem_percent,
            net_io: line.net_io,
            block_io: line.block_io,
        })
        .collect()
}

/// Container ids as `docker ps --no-trunc` prints them (or their short form).
fn checked_id(id: &str) -> Result<&str, String> {
    if (12..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(id)
    } else {
        Err(format!("'{id}' is not a container id"))
    }
}

async fn exec(connection: &SshConnection, command: &str) -> Result<crate::ssh::conn::ExecOutput, String> {
    tokio::time::timeout(DOCKER_TIMEOUT, connection.exec(command, None, MAX_OUTPUT))
        .await
        .map_err(|_| "Docker took too long to answer".to_string())?
}

/// Run `docker <args>`. Returns the output and whether `sudo -n` was needed.
async fn docker(connection: &SshConnection, args: &str, sudo: Option<bool>) -> Result<(String, bool), String> {
    if sudo != Some(true) {
        let output = exec(connection, &format!("docker {args}")).await?;
        if output.exit_status == Some(0) {
            return Ok((output.stdout_text(), false));
        }
        let stderr = output.stderr_text();
        if output.exit_status == Some(127) {
            return Err("Docker isn't installed on this host (no docker command)".to_string());
        }
        if !stderr.to_lowercase().contains("permission denied") || sudo == Some(false) {
            let message = stderr.trim();
            return Err(if message.is_empty() { "docker failed".to_string() } else { message.to_string() });
        }
    }
    let output = exec(connection, &format!("sudo -n docker {args}")).await?;
    if output.exit_status == Some(0) {
        Ok((output.stdout_text(), true))
    } else {
        Err(
            "This user can't use Docker: add it to the docker group, or allow `sudo docker` without a password."
                .to_string(),
        )
    }
}

pub async fn list(connection: &SshConnection) -> Result<ContainerList, String> {
    let (output, sudo) = docker(connection, "ps -a --no-trunc --format '{{json .}}'", None).await?;
    Ok(ContainerList { containers: parse_ps(&output), sudo })
}

/// CPU and memory of the running containers (takes a couple of seconds).
pub async fn stats(connection: &SshConnection, sudo: bool) -> Result<Vec<ContainerStats>, String> {
    let (output, _) = docker(connection, "stats --no-stream --no-trunc --format '{{json .}}'", Some(sudo)).await?;
    Ok(parse_stats(&output))
}

pub async fn action(connection: &SshConnection, id: &str, action: &str, sudo: bool) -> Result<(), String> {
    let verb = match action {
        "start" | "stop" | "restart" | "pause" | "unpause" => action,
        "remove" => "rm",
        other => return Err(format!("Unknown container action '{other}'")),
    };
    docker(connection, &format!("{verb} {}", checked_id(id)?), Some(sudo)).await.map(|_| ())
}

/// The last `tail` lines of a container's output (stdout and stderr).
pub async fn logs(connection: &SshConnection, id: &str, tail: u32, sudo: bool) -> Result<String, String> {
    let (output, _) = docker(
        connection,
        &format!("logs --tail {} --timestamps {} 2>&1", tail.clamp(1, 100_000), checked_id(id)?),
        Some(sudo),
    )
    .await?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_ps_and_stats_json() {
        let ps = r#"{"Command":"\"/entrypoint.sh node…\"","CreatedAt":"2026-10-10 12:49:17 +0700 WIB","ID":"ffd026766fde1111111111111111111111111111111111111111111111111111","Image":"decolua/9router:latest","Names":"9router","Ports":"127.0.0.1:20128->20128/tcp","RunningFor":"5 days ago","State":"running","Status":"Up 2 days"}
{"ID":"8eeafa21336d","Image":"redis:7","Names":"cache","Status":"Exited (0) 3 hours ago"}
{"ID":"aaaaaaaaaaaa","Image":"x","Names":"old","Status":"Up 3 minutes (Paused)"}
not json
"#;
        let containers = parse_ps(ps);
        assert_eq!(containers.len(), 3);
        assert_eq!(containers[0].name, "9router");
        assert_eq!(containers[0].ports, "127.0.0.1:20128->20128/tcp");
        assert_eq!(containers[0].state, "running");
        // Without a State field it comes from the status.
        assert_eq!(containers[1].state, "exited");
        assert_eq!(containers[2].state, "paused");

        let stats = parse_stats(
            r#"{"BlockIO":"0B / 0B","CPUPerc":"0.15%","Container":"ffd0","ID":"ffd026766fde","MemPerc":"1.20%","MemUsage":"95MiB / 7.6GiB","Name":"9router","NetIO":"1kB / 2kB","PIDs":"11"}"#,
        );
        assert_eq!(stats[0].cpu_percent, "0.15%");
        assert_eq!(stats[0].mem_usage, "95MiB / 7.6GiB");
    }

    // SSH_TEST_* as in ssh::e2e_tests, plus DOCKER_TEST_IMAGE: an image that
    // is already on the server (nothing is pulled). Only a container created
    // here is touched, and it is removed at the end.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn docker_on_a_real_server() {
        use crate::ssh::e2e_tests::{no_progress, TestServer};
        let image = std::env::var("DOCKER_TEST_IMAGE").expect("DOCKER_TEST_IMAGE");
        let server = TestServer::from_env();
        let db = std::sync::Arc::new(crate::db::Database::in_memory().unwrap());
        let pool = crate::ssh::ConnectionPool::new();
        let (connection, _) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
        let name = format!("termimus-e2e-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let created = connection
            .exec(
                &format!("docker run -d --init --name {name} --entrypoint sh {image} -c 'echo hello from {name}; sleep 600'"),
                None,
                4096,
            )
            .await
            .unwrap();
        let id = created.stdout_text().trim().to_string();
        assert_eq!(created.exit_status, Some(0), "{}", created.stderr_text());

        let state = |list: &ContainerList| list.containers.iter().find(|c| c.id == id).map(|c| c.state.clone());
        let listed = list(&connection).await.unwrap();
        assert_eq!(listed.containers.iter().find(|c| c.id == id).unwrap().name, name);
        assert_eq!(state(&listed).as_deref(), Some("running"));
        let sudo = listed.sudo;

        action(&connection, &id, "pause", sudo).await.unwrap();
        assert_eq!(state(&list(&connection).await.unwrap()).as_deref(), Some("paused"));
        action(&connection, &id, "unpause", sudo).await.unwrap();
        assert!(stats(&connection, sudo).await.unwrap().iter().any(|s| s.id == id));
        assert!(logs(&connection, &id, 50, sudo).await.unwrap().contains(&format!("hello from {name}")));

        // The shell tab the Docker panel opens: a PTY running `docker exec -it`
        // (the same command DockerView builds).
        let mut shell = connection.open_session().await.unwrap();
        shell.request_pty(true, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
        let exec = format!(
            "{}docker exec -it {id} sh -c \"command -v bash >/dev/null 2>&1 && exec bash || exec sh\"",
            if sudo { "sudo -n " } else { "" }
        );
        shell.exec(true, exec.as_str()).await.unwrap();
        shell.data(&b"echo inside-$((20+22)); exit\n"[..]).await.unwrap();
        let out = crate::ssh::e2e_tests::read_until(&mut shell, "inside-42").await;
        assert!(out.contains("inside-42"), "{out}");
        let _ = shell.close().await;
        action(&connection, &id, "stop", sudo).await.unwrap();
        assert_eq!(state(&list(&connection).await.unwrap()).as_deref(), Some("exited"));
        action(&connection, &id, "remove", sudo).await.unwrap();
        assert_eq!(state(&list(&connection).await.unwrap()), None);
        assert!(action(&connection, &id, "explode", sudo).await.is_err());
    }

    #[test]
    fn only_container_ids_reach_the_shell() {
        assert!(checked_id("ffd026766fde").is_ok());
        assert!(checked_id("ffd026766fde; rm -rf /").is_err());
        assert!(checked_id("abc").is_err());
    }
}
