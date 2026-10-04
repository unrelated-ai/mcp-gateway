use crate::config;
use anyhow::{Context as _, bail};
use std::{fs, path::PathBuf};

const SKILL_MD: &str = include_str!("../assets/unrelated-tools/SKILL.md");
const OPENAI_YAML: &str = include_str!("../assets/unrelated-tools/agents/openai.yaml");

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SkillHost {
    Codex,
    ClaudeCode,
}

pub fn install(host: SkillHost, force: bool) -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine the user home directory")?;
    install_at(
        host,
        force,
        &home,
        std::env::var_os("CODEX_HOME").map(PathBuf::from),
    )
}

fn install_at(
    host: SkillHost,
    force: bool,
    home: &std::path::Path,
    codex_home: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    let root = match host {
        SkillHost::Codex => codex_home
            .unwrap_or_else(|| home.join(".codex"))
            .join("skills"),
        SkillHost::ClaudeCode => home.join(".claude/skills"),
    };
    let target = root.join("unrelated-tools");
    if target.exists() {
        if !force {
            bail!(
                "skill already exists at {}; pass --force to replace it",
                target.display()
            );
        }
        fs::remove_dir_all(&target)
            .with_context(|| format!("failed to replace {}", target.display()))?;
    }
    config::create_private_dir(&target)?;
    fs::write(target.join("SKILL.md"), SKILL_MD)?;
    if matches!(host, SkillHost::Codex) {
        config::create_private_dir(&target.join("agents"))?;
        fs::write(target.join("agents/openai.yaml"), OPENAI_YAML)?;
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_skill_has_required_shape() {
        assert!(SKILL_MD.starts_with("---\nname: unrelated-tools\ndescription:"));
        assert!(SKILL_MD.contains("unrelated --json tools search"));
        assert!(OPENAI_YAML.contains("$unrelated-tools"));
        assert!(!SKILL_MD.contains("TODO"));
    }

    #[test]
    fn installs_for_both_hosts_and_requires_force_to_replace() {
        let temp = tempfile::tempdir().unwrap();
        let codex = install_at(SkillHost::Codex, false, temp.path(), None).unwrap();
        assert!(codex.join("SKILL.md").is_file());
        assert!(codex.join("agents/openai.yaml").is_file());
        assert!(install_at(SkillHost::Codex, false, temp.path(), None).is_err());
        assert!(install_at(SkillHost::Codex, true, temp.path(), None).is_ok());

        let claude = install_at(SkillHost::ClaudeCode, false, temp.path(), None).unwrap();
        assert!(claude.join("SKILL.md").is_file());
        assert!(!claude.join("agents/openai.yaml").exists());
    }
}
