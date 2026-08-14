use crate::{DetectorError, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum ScanMode {
    #[default]
    SingleAsn,
    BatchAsn,
    SingleIp,
    BatchIp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnTask {
    pub asn: u32,
    pub ports: String,
    pub tls: bool,
}

impl AsnTask {
    pub fn parse_line(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 3 {
            return Err(DetectorError::InvalidTarget(format!(
                "invalid ASN task line: {line}, expected format ASN:PORT:TLS"
            )));
        }
        let asn = parts[0].parse::<u32>().map_err(|_| {
            DetectorError::InvalidTarget(format!("invalid ASN number: {}", parts[0]))
        })?;
        let ports = parts[1].to_string();
        let tls_raw = parts[2].trim();
        let tls = matches!(
            tls_raw,
            "1" | "true" | "True" | "TRUE" | "yes" | "YES" | "Y" | "y"
        );
        Ok(Self { asn, ports, tls })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasscanConfig {
    pub interface: Option<String>,
    pub rate: u64,
    pub wait_seconds: u64,
    pub masscan_binary_path: Option<PathBuf>,
    pub asn_cache_dir: PathBuf,
    pub iface_setting_file: PathBuf,
    pub user_agent: String,
}

impl MasscanConfig {
    pub fn new() -> Self {
        Self {
            interface: None,
            rate: 10000,
            wait_seconds: 3,
            masscan_binary_path: None,
            asn_cache_dir: PathBuf::from("asn"),
            iface_setting_file: PathBuf::from("setting.txt"),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
}

pub struct MasscanScanner {
    pub cfg: MasscanConfig,
}

impl MasscanScanner {
    pub fn new(cfg: MasscanConfig) -> Self {
        Self { cfg }
    }

    pub fn resolve_masscan_cmd(&self) -> PathBuf {
        if let Some(p) = self.cfg.masscan_binary_path.as_ref()
            && p.exists()
        {
            return p.clone();
        }
        let local = PathBuf::from("./masscan");
        if local.exists() {
            return local;
        }
        PathBuf::from("masscan")
    }

    pub fn check_masscan_available(&self) -> Result<PathBuf> {
        let cmd = self.resolve_masscan_cmd();
        let is_local = cmd.is_relative() || cmd.parent().is_some() && cmd != *"masscan";
        if is_local && cmd.exists() {
            return Ok(cmd);
        }
        if cmd == *"masscan" {
            let output = Command::new(&cmd)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if output.is_ok() {
                return Ok(cmd);
            }
        }
        if cmd.exists() {
            return Ok(cmd);
        }
        Err(DetectorError::DataSource(format!(
            "masscan binary not found. Please install masscan or place it at {}",
            cmd.display()
        )))
    }

    #[cfg(target_os = "linux")]
    pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
        let content = std::fs::read_to_string("/proc/net/dev").map_err(|e| DetectorError::Io(e))?;
        let mut out = Vec::new();
        for line in content.lines().skip(2) {
            if let Some((name, _rest)) = line.split_once(':') {
                let trimmed = name.trim();
                if !trimmed.is_empty() && trimmed != "lo" {
                    out.push(NetworkInterface {
                        name: trimmed.to_string(),
                    });
                }
            }
        }
        Ok(out)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(DetectorError::Io)?;
        let local_addr = socket.local_addr().map_err(DetectorError::Io)?;
        let ip = local_addr.ip();
        let _ = ip;
        Ok(vec![NetworkInterface {
            name: "default".into(),
        }])
    }

    pub fn resolve_interface(&self) -> Result<String> {
        if let Some(iface) = self.cfg.interface.as_ref() {
            return Ok(iface.clone());
        }
        if self.cfg.iface_setting_file.exists()
            && let Ok(content) = std::fs::read_to_string(&self.cfg.iface_setting_file)
        {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
        let ifaces = Self::list_interfaces()?;
        match ifaces.len() {
            0 => Err(DetectorError::DataSource(
                "no network interfaces detected".into(),
            )),
            1 => Ok(ifaces[0].name.clone()),
            _ => Err(DetectorError::DataSource(format!(
                "multiple network interfaces detected ({:?}); please set --interface or write the name to {}",
                ifaces.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
                self.cfg.iface_setting_file.display()
            ))),
        }
    }

    pub fn save_interface_setting(&self, name: &str) -> Result<()> {
        if let Some(parent) = self.cfg.iface_setting_file.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.cfg.iface_setting_file, name)?;
        Ok(())
    }

    pub async fn fetch_asn_cidrs(&self, asn: u32) -> Result<Vec<String>> {
        std::fs::create_dir_all(&self.cfg.asn_cache_dir)?;
        let cache_file = self.cfg.asn_cache_dir.join(asn.to_string());
        if cache_file.exists() {
            let content = std::fs::read_to_string(&cache_file)?;
            let lines = content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            return Ok(lines);
        }
        let url = format!("https://whois.ipip.net/AS{}", asn);
        let client = reqwest::Client::builder()
            .user_agent(self.cfg.user_agent.as_str())
            .build()
            .map_err(DetectorError::Network)?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(DetectorError::Network)?;
        let html = resp.text().await.map_err(DetectorError::Network)?;
        let cidrs = parse_ipip_asn_html(&html, asn);
        let content = cidrs.join("\n");
        std::fs::write(&cache_file, content)?;
        Ok(cidrs)
    }

    pub async fn scan_cidrs(&self, cidrs: &[String], ports: &str) -> Result<Vec<OpenPort>> {
        if cidrs.is_empty() {
            return Ok(Vec::new());
        }
        let tmp_ipl = tempfile::NamedTempFile::new().map_err(DetectorError::Io)?;
        let ipl_path = tmp_ipl.path().to_path_buf();
        let data = cidrs.join("\n");
        std::fs::write(&ipl_path, data)?;
        let output_path = self.run_masscan(Some(&ipl_path), None, ports)?;
        let result = parse_masscan_output(&output_path)?;
        let _ = std::fs::remove_file(output_path);
        Ok(result)
    }

    pub async fn scan_ips(&self, ips: &[IpAddr], ports: &str) -> Result<Vec<OpenPort>> {
        if ips.is_empty() {
            return Ok(Vec::new());
        }
        let tmp_ipl = tempfile::NamedTempFile::new().map_err(DetectorError::Io)?;
        let ipl_path = tmp_ipl.path().to_path_buf();
        let data: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        std::fs::write(&ipl_path, data.join("\n"))?;
        let output_path = self.run_masscan(Some(&ipl_path), None, ports)?;
        let result = parse_masscan_output(&output_path)?;
        let _ = std::fs::remove_file(output_path);
        Ok(result)
    }

    pub async fn scan_single_ip(&self, ip: IpAddr, ports: &str) -> Result<Vec<OpenPort>> {
        let output_path = self.run_masscan(None, Some(&ip.to_string()), ports)?;
        let result = parse_masscan_output(&output_path)?;
        let _ = std::fs::remove_file(output_path);
        Ok(result)
    }

    fn run_masscan(
        &self,
        ilist_path: Option<&Path>,
        single_target: Option<&str>,
        ports: &str,
    ) -> Result<PathBuf> {
        let binary = self.check_masscan_available()?;
        let iface = self.resolve_interface()?;
        let output = tempfile::NamedTempFile::new().map_err(DetectorError::Io)?;
        let output_path = output.into_temp_path();
        let persist_path = output_path.keep().map_err(|e| DetectorError::Io(e.error))?;

        let mut cmd = Command::new(&binary);
        cmd.arg("-p").arg(ports);
        if let Some(path) = ilist_path {
            cmd.arg("-iL").arg(path);
        } else if let Some(target) = single_target {
            cmd.arg(target);
        }
        cmd.arg("--wait")
            .arg(self.cfg.wait_seconds.to_string())
            .arg("--rate")
            .arg(self.cfg.rate.to_string())
            .arg("-oL")
            .arg(&persist_path)
            .arg("--interface")
            .arg(&iface)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = cmd.status().map_err(DetectorError::Io)?;
        if !status.success() {
            let _ = std::fs::remove_file(&persist_path);
            return Err(DetectorError::Http(format!(
                "masscan exited with status {:?}",
                status.code()
            )));
        }
        Ok(persist_path)
    }

    pub fn read_ip_list_file(path: &Path) -> Result<Vec<IpAddr>> {
        let content = std::fs::read_to_string(path).map_err(DetectorError::Io)?;
        let mut out = Vec::new();
        for line in content.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let ip = trimmed
                .parse::<IpAddr>()
                .map_err(|_| DetectorError::InvalidIp(trimmed.to_string()))?;
            out.push(ip);
        }
        Ok(out)
    }

    pub fn read_asn_task_file(path: &Path) -> Result<Vec<AsnTask>> {
        let content = std::fs::read_to_string(path).map_err(DetectorError::Io)?;
        let mut out = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            match AsnTask::parse_line(trimmed) {
                Ok(t) => out.push(t),
                Err(e) => tracing::warn!("skip ASN task line {}: {}", i, e),
            }
        }
        Ok(out)
    }
}

fn parse_ipip_asn_html(html: &str, asn: u32) -> Vec<String> {
    let needle = format!("/AS{}/", asn);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in html.lines() {
        for segment in line.split_whitespace() {
            if segment.contains(&needle) {
                let cleaned =
                    segment.trim_matches(|c: char| c == '"' || c == '\'' || c == '>' || c == '<');
                if let Some(idx) = cleaned.find(&needle) {
                    let after = &cleaned[idx + needle.len()..];
                    let cidr_candidate: String = after
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '/' || *c == ':')
                        .collect();
                    if !cidr_candidate.contains(':')
                        && cidr_candidate.contains('/')
                        && seen.insert(cidr_candidate.clone())
                    {
                        out.push(cidr_candidate);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        for line in html.lines() {
            let re = regex_fallback(line);
            for cidr in re {
                if seen.insert(cidr.clone()) {
                    out.push(cidr);
                }
            }
        }
    }
    out
}

fn regex_fallback(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut dots = 0usize;
        let mut ok = true;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() {
                i += 1;
                continue;
            }
            if c == b'.' {
                dots += 1;
                if dots > 3 {
                    ok = false;
                    break;
                }
                i += 1;
                continue;
            }
            break;
        }
        if !ok || dots != 3 {
            i += 1;
            continue;
        }
        let ip_part = &line[start..i];
        if i < bytes.len() && bytes[i] == b'/' {
            i += 1;
            let pfx_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if pfx_start < i {
                let prefix = &line[pfx_start..i];
                if let Ok(p) = prefix.parse::<u8>()
                    && p <= 32
                {
                    out.push(format!("{}/{}", ip_part, p));
                    continue;
                }
            }
        }
    }
    out
}

pub fn parse_masscan_output(path: &Path) -> Result<Vec<OpenPort>> {
    let content = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[0] != "open" || parts[1] != "tcp" {
            continue;
        }
        let port = match parts[2].parse::<u16>() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let ip_str = parts.get(3).copied().unwrap_or("");
        let ip = match ip_str.parse::<IpAddr>() {
            Ok(i) => i,
            Err(_) => continue,
        };
        out.push(OpenPort { ip, port });
    }
    Ok(out)
}

pub fn clear_cache(asn_dir: &Path, setting_file: &Path) -> Result<()> {
    if asn_dir.exists() {
        let _ = std::fs::remove_dir_all(asn_dir);
    }
    if setting_file.exists() {
        let _ = std::fs::remove_file(setting_file);
    }
    for f in ["ip.txt", "data.txt"] {
        let p = PathBuf::from(f);
        if p.exists() {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ScanPipelineConfig {
    pub masscan: MasscanConfig,
    pub detector_concurrency: usize,
    pub speedtest: bool,
    pub speedtest_threads: usize,
    pub output_dir: PathBuf,
}

impl Default for ScanPipelineConfig {
    fn default() -> Self {
        Self {
            masscan: MasscanConfig::new(),
            detector_concurrency: 100,
            speedtest: false,
            speedtest_threads: 3,
            output_dir: PathBuf::from("."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn masscan_config_default_values() {
        let cfg = MasscanConfig::new();
        assert_eq!(cfg.rate, 10000);
        assert_eq!(cfg.wait_seconds, 3);
        assert_eq!(cfg.asn_cache_dir, PathBuf::from("asn"));
        assert_eq!(cfg.iface_setting_file, PathBuf::from("setting.txt"));
        assert!(cfg.interface.is_none());
        assert!(!cfg.user_agent.is_empty());
    }

    #[test]
    fn scan_mode_default_is_single_asn() {
        assert_eq!(ScanMode::default(), ScanMode::SingleAsn);
    }

    #[test]
    fn asn_task_parse_line_valid() {
        let t = AsnTask::parse_line("45102:443:1").unwrap();
        assert_eq!(t.asn, 45102);
        assert_eq!(t.ports, "443");
        assert!(t.tls);

        let t2 = AsnTask::parse_line("132203:80:0").unwrap();
        assert_eq!(t2.asn, 132203);
        assert_eq!(t2.ports, "80");
        assert!(!t2.tls);

        let t3 = AsnTask::parse_line("13335:443,8443:1").unwrap();
        assert_eq!(t3.asn, 13335);
        assert_eq!(t3.ports, "443,8443");
        assert!(t3.tls);
    }

    #[test]
    fn asn_task_parse_line_tls_bool_aliases() {
        assert!(AsnTask::parse_line("1:80:yes").unwrap().tls);
        assert!(AsnTask::parse_line("1:80:Y").unwrap().tls);
        assert!(AsnTask::parse_line("1:80:true").unwrap().tls);
        assert!(!AsnTask::parse_line("1:80:n").unwrap().tls);
        assert!(!AsnTask::parse_line("1:80:false").unwrap().tls);
    }

    #[test]
    fn asn_task_parse_line_invalid() {
        assert!(AsnTask::parse_line("").is_err());
        assert!(AsnTask::parse_line("45102").is_err());
        assert!(AsnTask::parse_line("bad:443:1").is_err());
    }

    #[test]
    fn open_port_struct() {
        let op = OpenPort {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 443,
        };
        assert_eq!(op.port, 443);
        assert_eq!(op.ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_masscan_output_format() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("masscan.txt");
        let sample = "\
#masscan
open tcp 443 104.16.132.229 1710000000
open tcp 8443 104.17.200.10 1710000001
# end
";
        std::fs::write(&p, sample).unwrap();
        let parsed = parse_masscan_output(&p).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].port, 443);
        assert_eq!(parsed[0].ip, IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)));
        assert_eq!(parsed[1].port, 8443);
    }

    #[test]
    fn parse_masscan_output_empty_or_comment_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("m2.txt");
        std::fs::write(&p, "# only header\n\n# end\n").unwrap();
        let parsed = parse_masscan_output(&p).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_masscan_output_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("m3.txt");
        std::fs::write(&p, "open tcp notanumber notanip x\nopen udp 123 1.2.3.4\n").unwrap();
        let parsed = parse_masscan_output(&p).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn regex_fallback_extracts_cidrs() {
        let line = "prefix: 192.168.1.0/24 other 10.0.0.0/8 end";
        let out = regex_fallback(line);
        assert!(out.contains(&"192.168.1.0/24".into()));
        assert!(out.contains(&"10.0.0.0/8".into()));
    }

    #[test]
    fn regex_fallback_rejects_ipv6() {
        let line = "2001:db8::/32 is v6 172.16.0.0/12 is v4";
        let out = regex_fallback(line);
        assert_eq!(out, vec!["172.16.0.0/12".to_string()]);
    }

    #[test]
    fn scan_pipeline_config_default_values() {
        let cfg = ScanPipelineConfig::default();
        assert_eq!(cfg.detector_concurrency, 100);
        assert!(!cfg.speedtest);
        assert_eq!(cfg.speedtest_threads, 3);
        assert_eq!(cfg.output_dir, PathBuf::from("."));
    }

    #[test]
    fn scanner_new_stores_config() {
        let cfg = MasscanConfig {
            rate: 50000,
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg.clone());
        assert_eq!(s.cfg.rate, 50000);
        assert_eq!(s.cfg.wait_seconds, cfg.wait_seconds);
    }

    #[test]
    fn scanner_resolve_masscan_prefers_local_binary_setting() {
        let cfg = MasscanConfig {
            masscan_binary_path: Some(PathBuf::from("/usr/local/bin/masscan")),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        let path = s.resolve_masscan_cmd();
        assert_eq!(path, PathBuf::from("/usr/local/bin/masscan"));
    }

    #[test]
    fn read_asn_task_file_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("as.txt");
        std::fs::write(&p, "\n# a comment\n45102:443:1\n   \n132203:80:0\n").unwrap();
        let tasks = MasscanScanner::read_asn_task_file(&p).unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].asn, 45102);
        assert_eq!(tasks[1].asn, 132203);
    }

    #[test]
    fn read_ip_list_file_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ips.txt");
        std::fs::write(&p, "\n# comment\n1.1.1.1\n\n2.2.2.2 # trailing\n").unwrap();
        let ips = MasscanScanner::read_ip_list_file(&p).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(ips[1], IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
    }

    #[test]
    fn clear_cache_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let asn_dir = dir.path().join("asn");
        let setting = dir.path().join("setting.txt");
        let ip_list = dir.path().join("ip.txt");
        std::fs::create_dir_all(&asn_dir).unwrap();
        std::fs::write(asn_dir.join("45102"), "x").unwrap();
        std::fs::write(&setting, "eth0").unwrap();
        std::fs::write(&ip_list, "temp").unwrap();
        clear_cache(&asn_dir, &setting).unwrap();
        assert!(!asn_dir.exists());
        assert!(!setting.exists());
        assert!(ip_list.exists());
        std::fs::remove_file(&ip_list).unwrap();
    }

    #[test]
    fn clear_cache_missing_dirs_noop() {
        let dir = tempfile::tempdir().unwrap();
        let asn_dir = dir.path().join("not-exist-asn");
        let setting = dir.path().join("not-exist-setting.txt");
        clear_cache(&asn_dir, &setting).unwrap();
        assert!(!asn_dir.exists());
        assert!(!setting.exists());
    }

    #[test]
    fn clear_cache_runs_idempotent_multiple_calls() {
        let dir = tempfile::tempdir().unwrap();
        let asn_dir = dir.path().join("asn2");
        let setting = dir.path().join("s2.txt");
        std::fs::create_dir_all(&asn_dir).unwrap();
        std::fs::write(&setting, "x").unwrap();
        clear_cache(&asn_dir, &setting).unwrap();
        clear_cache(&asn_dir, &setting).unwrap();
        clear_cache(&asn_dir, &setting).unwrap();
    }

    #[test]
    fn save_interface_setting_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MasscanConfig {
            iface_setting_file: dir.path().join("iface.txt"),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        s.save_interface_setting("eth0").unwrap();
        let content = std::fs::read_to_string(&s.cfg.iface_setting_file).unwrap();
        assert_eq!(content.trim(), "eth0");
    }

    #[test]
    fn resolve_masscan_cmd_falls_back_to_path_binary() {
        let cfg = MasscanConfig::new();
        let s = MasscanScanner::new(cfg);
        let path = s.resolve_masscan_cmd();
        assert_eq!(path, PathBuf::from("masscan"));
    }

    #[test]
    fn resolve_masscan_cmd_prefers_local_relative_binary() {
        let local = PathBuf::from("./masscan");
        if local.exists() {
            let cfg = MasscanConfig::new();
            let s = MasscanScanner::new(cfg);
            let path = s.resolve_masscan_cmd();
            assert_eq!(path, local);
        }
    }

    #[test]
    fn resolve_masscan_cmd_custom_path_nonexistent_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("definitely-not-masscan-binary");
        let cfg = MasscanConfig {
            masscan_binary_path: Some(missing),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        assert_eq!(s.resolve_masscan_cmd(), PathBuf::from("masscan"));
    }

    #[test]
    fn resolve_masscan_cmd_custom_path_existing_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("my-masscan");
        std::fs::write(&fake, "dummy").unwrap();
        let cfg = MasscanConfig {
            masscan_binary_path: Some(fake.clone()),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        assert_eq!(s.resolve_masscan_cmd(), fake);
    }

    #[test]
    fn check_masscan_available_existing_custom_path_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("existing-custom-masscan");
        std::fs::write(&fake, "placeholder").unwrap();
        let cfg = MasscanConfig {
            masscan_binary_path: Some(fake.clone()),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        let got = s.check_masscan_available().unwrap();
        assert_eq!(got, fake);
    }

    #[test]
    fn check_masscan_available_when_installed_in_ci() {
        if std::env::var("CFRP_CI").is_ok() {
            let cfg = MasscanConfig::new();
            let s = MasscanScanner::new(cfg);
            let res = s.check_masscan_available();
            assert!(res.is_ok(), "expected masscan to be available in CI");
            let path = res.unwrap();
            assert!(path.file_name().is_some());
        }
    }

    #[test]
    fn resolve_interface_uses_explicit_config() {
        let cfg = MasscanConfig {
            interface: Some("eth123".into()),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        let iface = s.resolve_interface().unwrap();
        assert_eq!(iface, "eth123");
    }

    #[test]
    fn resolve_interface_reads_from_setting_file() {
        let dir = tempfile::tempdir().unwrap();
        let setting_file = dir.path().join("iface.txt");
        std::fs::write(&setting_file, " eth99 \n").unwrap();
        let nonexistent = dir.path().join("does-not-exist-for-interface-fallback.txt");
        let cfg = MasscanConfig {
            interface: None,
            iface_setting_file: setting_file.clone(),
            asn_cache_dir: nonexistent,
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        let iface = s.resolve_interface().unwrap();
        assert_eq!(iface, "eth99");
    }

    #[test]
    fn resolve_interface_setting_file_empty_or_missing_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let empty_file = dir.path().join("empty.txt");
        std::fs::write(&empty_file, "   \n\t\n").unwrap();
        let cfg = MasscanConfig {
            interface: None,
            iface_setting_file: empty_file,
            asn_cache_dir: dir.path().join("asn"),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        let iface = s.resolve_interface().unwrap();
        #[cfg(target_os = "linux")]
        assert!(!iface.is_empty());
        #[cfg(not(target_os = "linux"))]
        assert_eq!(iface, "default");
    }

    #[test]
    fn list_interfaces_nonlinux_returns_default() {
        #[cfg(not(target_os = "linux"))]
        {
            let ifaces = MasscanScanner::list_interfaces().unwrap();
            assert_eq!(ifaces.len(), 1);
            assert_eq!(ifaces[0].name, "default");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn list_interfaces_linux_parses_proc_net_dev() {
        let ifaces = MasscanScanner::list_interfaces().unwrap();
        assert!(
            !ifaces.is_empty(),
            "expected at least one network interface"
        );
        for iface in &ifaces {
            assert_ne!(iface.name, "lo");
            assert!(!iface.name.is_empty());
        }
    }

    #[test]
    fn save_interface_setting_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("iface.txt");
        let cfg = MasscanConfig {
            iface_setting_file: nested.clone(),
            ..MasscanConfig::new()
        };
        let s = MasscanScanner::new(cfg);
        s.save_interface_setting("ens5").unwrap();
        assert!(nested.exists());
        let content = std::fs::read_to_string(&nested).unwrap();
        assert_eq!(content.trim(), "ens5");
    }

    #[test]
    fn parse_ipip_asn_html_extracts_cidrs_from_link_hrefs() {
        let html = r#"
        <html>
          <a href="/AS45102/104.16.0.0/12">104.16.0.0/12</a>
          <a href='/AS45102/172.64.0.0/13'>172.64.0.0/13</a>
          <span class="x" data-cidr="/AS45102/104.28.0.0/14">nope</span>
          <a href="/AS13335/1.1.1.0/24">other asn</a>
        </html>
        "#;
        let out = parse_ipip_asn_html(html, 45102);
        assert!(out.contains(&"104.16.0.0/12".into()));
        assert!(out.contains(&"172.64.0.0/13".into()));
        assert!(out.contains(&"104.28.0.0/14".into()));
        assert!(!out.iter().any(|c| c.starts_with("1.1.1.")));
    }

    #[test]
    fn parse_ipip_asn_html_deduplicates() {
        let html = r#"
        <a href="/AS1/10.0.0.0/8">a</a>
        <a href="/AS1/10.0.0.0/8">dup</a>
        <a href="/AS1/10.0.0.0/8">again</a>
        "#;
        let out = parse_ipip_asn_html(html, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], "10.0.0.0/8");
    }

    #[test]
    fn parse_ipip_asn_html_regex_fallback_works() {
        let html = "plain text with 192.168.0.0/16 and 10.0.0.0/8 mentioned without links";
        let out = parse_ipip_asn_html(html, 9999);
        assert!(out.contains(&"192.168.0.0/16".into()));
        assert!(out.contains(&"10.0.0.0/8".into()));
    }

    #[test]
    fn parse_ipip_asn_html_rejects_ipv6_candidates() {
        let html = r#"
        <a href="/AS1/2001:db8::/32">v6</a>
        plain 2001:db8::/32 here
        "#;
        let out = parse_ipip_asn_html(html, 1);
        for cidr in &out {
            assert!(!cidr.contains(':'));
        }
    }
}
