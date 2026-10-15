//! Server stats (CPU, memory, disks, network, uptime) read from `/proc` and
//! `df` with one exec per sample. CPU usage and network rates come from the
//! difference between two samples.

use serde::Serialize;

/// Prints the sections `parse` reads. POSIX sh; Linux (`/proc`) only.
pub const STATS_SCRIPT: &str = r#"export LC_ALL=C
echo "@@hostname"; hostname 2>/dev/null || cat /proc/sys/kernel/hostname
echo "@@os"; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
echo "@@kernel"; uname -sr
echo "@@uptime"; cat /proc/uptime
echo "@@loadavg"; cat /proc/loadavg
echo "@@cpus"; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo
echo "@@stat"; head -n 1 /proc/stat
echo "@@meminfo"; cat /proc/meminfo
echo "@@df"; df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null || df -P -k
echo "@@net"; cat /proc/net/dev
echo "@@end""#;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiskUsage {
    pub mount: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostStats {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub load: [f64; 3],
    pub cpu_count: u32,
    /// Busy share of all CPUs since the previous sample; `None` on the first.
    pub cpu_percent: Option<f64>,
    pub mem_total_bytes: u64,
    /// Total minus what is available (page cache counts as free).
    pub mem_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disks: Vec<DiskUsage>,
    /// Bytes per second over all interfaces except loopback, since the
    /// previous sample.
    pub net_rx_rate: Option<f64>,
    pub net_tx_rate: Option<f64>,
}

/// What the next sample needs from this one.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Counters {
    cpu_busy: u64,
    cpu_total: u64,
    net_rx: u64,
    net_tx: u64,
    /// Seconds (`/proc/uptime`), as the clock the rates are measured with.
    at: f64,
}

fn sections(output: &str) -> std::collections::HashMap<&str, Vec<&str>> {
    let mut map = std::collections::HashMap::new();
    let mut current: Option<&str> = None;
    for line in output.lines() {
        if let Some(name) = line.strip_prefix("@@") {
            current = Some(name.trim());
            map.entry(name.trim()).or_insert_with(Vec::new);
        } else if let Some(name) = current {
            map.entry(name).or_insert_with(Vec::new).push(line);
        }
    }
    map
}

/// Parse one sample; `previous` gives the CPU and network rates.
pub fn parse(output: &str, previous: Option<&Counters>) -> Result<(HostStats, Counters), String> {
    let sections = sections(output);
    let first = |name: &str| sections.get(name).and_then(|lines| lines.first()).map(|l| l.trim()).unwrap_or_default();

    let meminfo: std::collections::HashMap<&str, u64> = sections
        .get("meminfo")
        .map(|lines| {
            lines
                .iter()
                .filter_map(|line| {
                    let (key, rest) = line.split_once(':')?;
                    let kib = rest.split_whitespace().next()?.parse::<u64>().ok()?;
                    Some((key.trim(), kib * 1024))
                })
                .collect()
        })
        .unwrap_or_default();
    let Some(&mem_total) = meminfo.get("MemTotal") else {
        return Err("Server stats need a Linux host (no /proc/meminfo)".to_string());
    };
    let mem_available = meminfo.get("MemAvailable").copied().unwrap_or_else(|| {
        // Kernels before 3.14: free + buffers + page cache.
        ["MemFree", "Buffers", "Cached"].iter().filter_map(|k| meminfo.get(k)).sum()
    });
    let swap_total = meminfo.get("SwapTotal").copied().unwrap_or_default();
    let swap_free = meminfo.get("SwapFree").copied().unwrap_or_default();

    let uptime: f64 = first("uptime").split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or_default();
    let mut load = [0.0; 3];
    for (slot, value) in load.iter_mut().zip(first("loadavg").split_whitespace()) {
        *slot = value.parse().unwrap_or_default();
    }

    // cpu  user nice system idle iowait irq softirq steal guest guest_nice
    let cpu: Vec<u64> = first("stat").split_whitespace().skip(1).filter_map(|v| v.parse().ok()).collect();
    // guest time is already counted in user/nice.
    let cpu_total: u64 = cpu.iter().take(8).sum();
    let cpu_idle = cpu.get(3).copied().unwrap_or_default() + cpu.get(4).copied().unwrap_or_default();
    let cpu_busy = cpu_total.saturating_sub(cpu_idle);

    let (mut net_rx, mut net_tx) = (0u64, 0u64);
    for line in sections.get("net").into_iter().flatten() {
        let Some((name, counters)) = line.split_once(':') else { continue };
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<u64> = counters.split_whitespace().filter_map(|v| v.parse().ok()).collect();
        if fields.len() >= 9 {
            net_rx += fields[0];
            net_tx += fields[8];
        }
    }

    let counters = Counters { cpu_busy, cpu_total, net_rx, net_tx, at: uptime };
    let (cpu_percent, net_rx_rate, net_tx_rate) = match previous {
        // A reboot in between resets the counters: no rates this time.
        Some(prev) if counters.at > prev.at && cpu_total >= prev.cpu_total => {
            let total = (cpu_total - prev.cpu_total) as f64;
            let busy = cpu_busy.saturating_sub(prev.cpu_busy) as f64;
            let seconds = counters.at - prev.at;
            (
                (total > 0.0).then(|| (busy / total * 100.0).clamp(0.0, 100.0)),
                Some(net_rx.saturating_sub(prev.net_rx) as f64 / seconds),
                Some(net_tx.saturating_sub(prev.net_tx) as f64 / seconds),
            )
        }
        _ => (None, None, None),
    };

    let mut disks = Vec::new();
    // Filesystem 1024-blocks Used Available Capacity Mounted-on
    for line in sections.get("df").into_iter().flatten().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let (Ok(total), Ok(used)) = (fields[1].parse::<u64>(), fields[2].parse::<u64>()) else { continue };
        let mount = fields[5..].join(" ");
        // Snap/loop images and bind mounts of the same device add noise.
        if total == 0 || fields[0].starts_with("/dev/loop") || disks.iter().any(|d: &DiskUsage| d.filesystem == fields[0]) {
            continue;
        }
        disks.push(DiskUsage {
            mount,
            filesystem: fields[0].to_string(),
            total_bytes: total * 1024,
            used_bytes: used * 1024,
        });
    }

    let stats = HostStats {
        hostname: first("hostname").to_string(),
        os: first("os").to_string(),
        kernel: first("kernel").to_string(),
        uptime_secs: uptime as u64,
        load,
        cpu_count: first("cpus").parse().unwrap_or(1),
        cpu_percent,
        mem_total_bytes: mem_total,
        mem_used_bytes: mem_total.saturating_sub(mem_available),
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
        disks,
        net_rx_rate,
        net_tx_rate,
    };
    Ok((stats, counters))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(uptime: &str, cpu: &str, rx: u64, tx: u64) -> String {
        format!(
            "@@hostname\nweb-1\n@@os\nUbuntu 24.04.1 LTS\n@@kernel\nLinux 6.8.0-45-generic\n\
             @@uptime\n{uptime} 9000.00\n@@loadavg\n0.52 0.40 0.31 1/234 5678\n@@cpus\n4\n\
             @@stat\ncpu  {cpu}\n\
             @@meminfo\nMemTotal:        8000000 kB\nMemFree:          500000 kB\nMemAvailable:    6000000 kB\nBuffers:           1000 kB\nCached:          100000 kB\nSwapTotal:       2000000 kB\nSwapFree:        1500000 kB\n\
             @@df\nFilesystem     1024-blocks     Used Available Capacity Mounted on\n\
             /dev/sda1         50000000 20000000  30000000      40% /\n\
             /dev/loop3           65536    65536         0     100% /snap/core/1\n\
             /dev/sdb1        100000000 10000000  90000000      10% /srv/data disk\n\
             /dev/sda1         50000000 20000000  30000000      40% /var/lib/docker\n\
             @@net\nInter-|   Receive                                                |  Transmit\n \
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
             lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0\n  \
             eth0: {rx} 100 0 0 0 0 0 0 {tx} 80 0 0 0 0 0 0\n@@end\n"
        )
    }

    #[test]
    fn first_sample_has_totals_but_no_rates() {
        let (stats, _) = parse(&sample("1000.00", "100 0 100 700 100 0 0 0 0 0", 5000, 2000), None).unwrap();
        assert_eq!(stats.hostname, "web-1");
        assert_eq!(stats.os, "Ubuntu 24.04.1 LTS");
        assert_eq!(stats.kernel, "Linux 6.8.0-45-generic");
        assert_eq!(stats.uptime_secs, 1000);
        assert_eq!(stats.load, [0.52, 0.40, 0.31]);
        assert_eq!(stats.cpu_count, 4);
        assert_eq!(stats.cpu_percent, None);
        assert_eq!(stats.mem_total_bytes, 8_000_000 * 1024);
        assert_eq!(stats.mem_used_bytes, 2_000_000 * 1024);
        assert_eq!(stats.swap_used_bytes, 500_000 * 1024);
        // Loop devices and a second mount of /dev/sda1 are left out; mount
        // points may contain spaces.
        assert_eq!(
            stats.disks.iter().map(|d| d.mount.as_str()).collect::<Vec<_>>(),
            ["/", "/srv/data disk"]
        );
        assert_eq!(stats.disks[0].used_bytes, 20_000_000 * 1024);
    }

    #[test]
    fn rates_come_from_the_previous_sample() {
        let (_, first) = parse(&sample("1000.00", "100 0 100 700 100 0 0 0 0 0", 5000, 2000), None).unwrap();
        // +200 busy of +400 total ticks, 2 seconds later.
        let (stats, _) =
            parse(&sample("1002.00", "250 0 150 850 150 0 0 0 0 0", 9000, 3000), Some(&first)).unwrap();
        assert_eq!(stats.cpu_percent, Some(50.0));
        assert_eq!(stats.net_rx_rate, Some(2000.0));
        assert_eq!(stats.net_tx_rate, Some(500.0));

        // After a reboot the counters start over: no rates.
        let (stats, _) = parse(&sample("5.00", "1 0 1 10 1 0 0 0 0 0", 10, 10), Some(&first)).unwrap();
        assert_eq!(stats.cpu_percent, None);
    }

    // SSH_TEST_* as in ssh::e2e_tests.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stats_from_a_real_server() {
        use crate::ssh::e2e_tests::{no_progress, TestServer};
        let server = TestServer::from_env();
        let db = std::sync::Arc::new(crate::db::Database::in_memory().unwrap());
        let pool = crate::ssh::ConnectionPool::new();
        let (connection, _) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
        let command = crate::ssh::conn::sh_command(STATS_SCRIPT);
        let output = connection.exec(&command, None, 1 << 18).await.unwrap();
        let (stats, counters) = parse(&output.stdout_text(), None).unwrap();
        assert!(!stats.hostname.is_empty() && !stats.kernel.is_empty());
        assert!(stats.mem_total_bytes > stats.mem_used_bytes && stats.mem_used_bytes > 0);
        assert!(stats.cpu_count >= 1 && stats.uptime_secs > 0);
        assert!(stats.disks.iter().any(|d| d.mount == "/"), "{:?}", stats.disks);

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let output = connection.exec(&command, None, 1 << 18).await.unwrap();
        let (stats, _) = parse(&output.stdout_text(), Some(&counters)).unwrap();
        let cpu = stats.cpu_percent.expect("second sample has CPU usage");
        assert!((0.0..=100.0).contains(&cpu));
        assert!(stats.net_rx_rate.is_some());
        println!("{stats:#?}");
    }

    #[test]
    fn non_linux_hosts_are_reported() {
        assert!(parse("@@hostname\nmac\n@@meminfo\n@@end\n", None).unwrap_err().contains("Linux"));
    }
}
