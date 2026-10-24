//! Interactive control panel using the same CLI operations as scripts.

mod storage;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal,
};

use super::{status, OutputOptions};
use crate::browsers::Browser;
use crate::config::{Config, CustomBrowserConfig, UpdateChannel};
use crate::{Error, Result};

const TABS: [&str; 6] = [
    "Overview",
    "Browsers",
    "Diagnostics",
    "Updates",
    "Logs",
    "Settings",
];
const SETTINGS: usize = 7;

struct App {
    tab: usize,
    selected: usize,
    setting: usize,
    scroll: usize,
    browsers: Vec<Browser>,
    status: status::StatusReport,
    config: Config,
    original: Vec<u8>,
    config_path: PathBuf,
    dirty: bool,
    output: String,
    logs: String,
    filter: String,
    warnings_only: bool,
    notice: String,
    input: Option<Input>,
    pending: Option<Pending>,
    quit: bool,
    executable: PathBuf,
}

struct Input {
    title: String,
    value: String,
    kind: InputKind,
}

enum InputKind {
    Search,
    Export,
    Hook(usize),
    Browser {
        step: usize,
        name: String,
        install: String,
        editing: Option<usize>,
    },
}

enum Pending {
    Command {
        label: String,
        args: Vec<String>,
        close_after: bool,
    },
    RemoveBrowser(usize),
    Quit,
}

impl App {
    fn load() -> Result<Self> {
        let config_path = crate::config::default_config_path()
            .ok_or_else(|| Error::other("Cannot resolve configuration directory"))?;
        let original = storage::read_config(&config_path)?;
        let config = crate::config::load_config_from(&config_path)?;
        let browsers = crate::browsers::detect_browsers()?;
        let status = status::build_status(
            &browsers,
            status::read_heartbeat(),
            status::current_cdm_version(),
        );
        Ok(Self { tab: 0, selected: 0, setting: 0, scroll: 0, browsers, status, config, original,
            config_path, dirty: false, output: "Select a browser and press d for passive diagnostics or t for an explicit browser test.".into(),
            logs: String::new(), filter: String::new(), warnings_only: false,
            notice: "Tab or 1–6: views · ↑/↓: select or scroll · ?: help · q: quit".into(),
            input: None, pending: None, quit: false, executable: std::env::current_exe()? })
    }

    fn refresh(&mut self) -> Result<()> {
        self.browsers = crate::browsers::detect_browsers()?;
        self.selected = self.selected.min(self.browsers.len().saturating_sub(1));
        self.status = status::build_status(
            &self.browsers,
            status::read_heartbeat(),
            status::current_cdm_version(),
        );
        if self.tab == 4 {
            self.logs = crate::log::log_dir().map_or_else(
                || Ok("Log directory unavailable.".into()),
                |p| storage::read_logs(&p),
            )?;
        }
        Ok(())
    }

    fn browser_name(&self) -> Result<String> {
        let browser = self.browsers.get(self.selected).ok_or_else(|| {
            Error::other("No browser selected. Run setup or add a custom path in Settings.")
        })?;
        if self
            .browsers
            .iter()
            .filter(|b| b.name.eq_ignore_ascii_case(&browser.name))
            .count()
            != 1
        {
            return Err(Error::other("Several installations share this name. Give custom installations distinct names before running an action."));
        }
        Ok(browser.name.clone())
    }

    fn confirm(&mut self, label: impl Into<String>, args: Vec<String>, close_after: bool) {
        self.pending = Some(Pending::Command {
            label: label.into(),
            args,
            close_after,
        });
    }

    fn execute(&mut self, args: &[String], terminal_state: &mut TerminalState) -> Result<()> {
        terminal_state.suspend()?;
        println!("Silvervine: {}\n", args.join(" "));
        let result = Command::new(&self.executable).args(args).status();
        self.output = match result {
            Ok(status) => format!("silvervine {}\n\nResult: {status}\nSee Logs for daemon history. Run diagnostics to collect a detailed report.", args.join(" ")),
            Err(error) => format!("Could not run operation: {error}"),
        };
        println!("\n{}\n\nPress Enter to return to Silvervine.", self.output);
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        terminal_state.resume()?;
        self.notice = self
            .output
            .lines()
            .find(|l| l.starts_with("Result:"))
            .unwrap_or("Operation finished; inspect the output and logs.")
            .into();
        self.refresh()?;
        Ok(())
    }

    fn diagnostics(&mut self) -> Result<()> {
        let browser = self.browser_name()?;
        self.tab = 2;
        self.scroll = 0;
        self.notice = "Collecting passive diagnostics…".into();
        draw(self)?;
        let output = Command::new(&self.executable)
            .args([
                "--no-color",
                "doctor",
                "--media-stack",
                "--browser",
                &browser,
            ])
            .output()?;
        self.output = String::from_utf8_lossy(&output.stdout).into_owned();
        self.output
            .push_str(&String::from_utf8_lossy(&output.stderr));
        self.notice = format!("Diagnostics completed: {} · x: save report", output.status);
        Ok(())
    }

    fn settings_rows(&self) -> Vec<String> {
        let hook =
            |value: &Option<String>| value.as_deref().unwrap_or("(default hook path)").to_owned();
        let mut rows = vec![
            format!("Update channel: {}", self.config.updates.channel.as_str()),
            format!("Automatic self-updates: {}", self.config.updates.auto_apply),
            format!(
                "Success notifications: {}",
                self.config.notifications.on_success
            ),
            format!(
                "Failure notifications: {}",
                self.config.notifications.on_failure
            ),
            format!("Pre-patch hook: {}", hook(&self.config.hooks.pre_patch)),
            format!("Post-patch hook: {}", hook(&self.config.hooks.post_patch)),
            format!("Post-update hook: {}", hook(&self.config.hooks.post_update)),
        ];
        rows.extend(self.config.browsers.iter().map(|b| {
            format!(
                "Custom browser: {} — {}",
                b.name,
                b.bundle_path
                    .as_ref()
                    .or(b.install_path.as_ref())
                    .map_or_else(String::new, |p| p.display().to_string())
            )
        }));
        rows
    }

    fn edit_setting(&mut self) {
        match self.setting {
            0 => {
                self.config.updates.channel = match self.config.updates.channel {
                    UpdateChannel::Stable => UpdateChannel::Preview,
                    UpdateChannel::Preview => UpdateChannel::Stable,
                };
                self.dirty = true;
                self.notice = "Channel changed in draft. Preview includes RCs; press s to save. Automatic installation is a separate setting.".into();
            }
            1 => {
                self.config.updates.auto_apply = !self.config.updates.auto_apply;
                self.dirty = true;
            }
            2 => {
                self.config.notifications.on_success = !self.config.notifications.on_success;
                self.dirty = true;
            }
            3 => {
                self.config.notifications.on_failure = !self.config.notifications.on_failure;
                self.dirty = true;
            }
            4..=6 => {
                let value = match self.setting {
                    4 => &self.config.hooks.pre_patch,
                    5 => &self.config.hooks.post_patch,
                    _ => &self.config.hooks.post_update,
                };
                self.input = Some(Input {
                    title: "Hook script path (empty restores default)".into(),
                    value: value.clone().unwrap_or_default(),
                    kind: InputKind::Hook(self.setting),
                });
            }
            index => {
                let index = index - SETTINGS;
                if let Some(browser) = self.config.browsers.get(index) {
                    self.input = Some(Input {
                        title: "Browser name".into(),
                        value: browser.name.clone(),
                        kind: InputKind::Browser {
                            step: 0,
                            name: String::new(),
                            install: String::new(),
                            editing: Some(index),
                        },
                    });
                }
            }
        }
    }

    fn save(&mut self) -> Result<()> {
        self.original = storage::save_config(&self.config_path, &self.original, &self.config)?;
        self.dirty = false;
        self.notice =
            "Configuration saved. Press r in Settings to restart the daemon and apply changes."
                .into();
        self.refresh()
    }

    fn report(&self) -> String {
        format!(
            "Silvervine {}\nPlatform: {} {}\nUpdate channel: {}\nAutomatic updates: {}\n\n{}\n",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            self.config.updates.channel.as_str(),
            self.config.updates.auto_apply,
            if self.tab == 4 {
                self.filtered_logs()
            } else {
                self.output.clone()
            }
        )
    }

    fn filtered_logs(&self) -> String {
        let filter = self.filter.to_lowercase();
        self.logs
            .lines()
            .filter(|line| line.to_lowercase().contains(&filter))
            .filter(|line| !self.warnings_only || line.contains("WARN") || line.contains("ERROR"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

struct TerminalState {
    active: bool,
}

impl TerminalState {
    fn new() -> Result<Self> {
        let mut state = Self { active: false };
        state.resume()?;
        Ok(state)
    }
    fn resume(&mut self) -> Result<()> {
        terminal::enable_raw_mode()?;
        self.active = true;
        crossterm::execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)?;
        Ok(())
    }
    fn suspend(&mut self) -> Result<()> {
        if self.active {
            terminal::disable_raw_mode()?;
            self.active = false;
            crossterm::execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen)?;
        }
        Ok(())
    }
}

impl Drop for TerminalState {
    fn drop(&mut self) {
        let _ = self.suspend();
    }
}

/// Open the terminal control panel.
///
/// # Errors
/// Returns configuration, terminal, or filesystem errors; interactive terminals are required.
pub fn run(output: OutputOptions) -> Result<()> {
    if output.json || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::other(
            "silvervine tui requires an interactive terminal and does not support --json",
        ));
    }
    let mut app = App::load()?;
    let mut terminal_state = TerminalState::new()?;
    let mut refreshed = Instant::now();
    while !app.quit {
        draw(&app)?;
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if let Err(error) = handle_key(&mut app, key, &mut terminal_state) {
                        app.notice = error.to_string();
                    }
                }
                _ => {}
            }
        }
        if refreshed.elapsed() >= Duration::from_secs(2) {
            if let Err(error) = app.refresh() {
                app.notice = error.to_string();
            }
            refreshed = Instant::now();
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent, terminal_state: &mut TerminalState) -> Result<()> {
    if app.input.is_some() {
        return input_key(app, key);
    }
    if app.pending.is_some() {
        return confirmation_key(app, key, terminal_state);
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        request_quit(app);
        return Ok(());
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => request_quit(app),
        KeyCode::Tab => { app.tab = (app.tab + 1) % TABS.len(); app.scroll = 0; app.refresh()?; }
        KeyCode::BackTab => { app.tab = (app.tab + TABS.len() - 1) % TABS.len(); app.scroll = 0; app.refresh()?; }
        KeyCode::Char(n @ '1'..='6') => { app.tab = n as usize - '1' as usize; app.scroll = 0; app.refresh()?; }
        KeyCode::Up | KeyCode::Char('k') => navigate(app, false),
        KeyCode::Down | KeyCode::Char('j') => navigate(app, true),
        KeyCode::PageUp => app.scroll = app.scroll.saturating_sub(10),
        KeyCode::PageDown => app.scroll = app.scroll.saturating_add(10),
        KeyCode::Home => app.scroll = 0,
        KeyCode::End => app.scroll = usize::MAX,
        KeyCode::Char('?') => app.notice = "1–6/Tab views · ↑↓ select/scroll · p patch · l launch · t browser test · d diagnostics · u self-update · w Widevine update · x export · Settings: Enter edit, a add, Delete remove, s save, r restart, g enable daemon, z disable daemon".into(),
        KeyCode::Char('x') => app.input = Some(Input { title: "Save displayed report to a new file".into(), value: format!("silvervine-report-{}.txt", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()), kind: InputKind::Export }),
        KeyCode::Char('d') => app.diagnostics()?,
        KeyCode::Char('p') => { let name = app.browser_name()?; app.confirm(format!("Patch {name}? Close the browser first."), vec!["patch".into(), name], false); }
        KeyCode::Char('t') => { let name = app.browser_name()?; app.confirm(format!("Open {name} for a live browser capability test?"), vec!["test".into(), "--browser".into(), name], false); }
        KeyCode::Char('l') => { let name = app.browser_name()?; app.confirm(format!("Verify and launch {name}?"), vec!["launch".into(), name], false); }
        KeyCode::Char('w') => app.confirm("Download Widevine and patch detected browsers? Close browsers first.", vec!["update".into(), "widevine".into()], false),
        KeyCode::Char('i') => app.confirm("Run setup, install Widevine, patch detected browsers, and enable the user daemon?", vec!["setup".into()], false),
        KeyCode::Char('u') => app.confirm(format!("Update Silvervine using the {} channel? The TUI will close afterward. Save Settings first to apply draft changes.", app.config.updates.channel.as_str()), vec!["update".into(), "self".into()], true),
        KeyCode::Char('v') if app.tab == 3 => app.execute(&["update".into(), "self".into(), "--dry-run".into()], terminal_state)?,
        KeyCode::Char('/') if app.tab == 4 => app.input = Some(Input { title: "Filter logs (empty shows all)".into(), value: app.filter.clone(), kind: InputKind::Search }),
        KeyCode::Char('!') if app.tab == 4 => { app.warnings_only = !app.warnings_only; app.scroll = 0; }
        KeyCode::Char('b') if app.tab == 4 => { app.filter = app.browser_name()?; app.scroll = 0; }
        _ if app.tab == 5 => settings_key(app, key)?,
        _ => {}
    }
    Ok(())
}

fn request_quit(app: &mut App) {
    if app.dirty {
        app.pending = Some(Pending::Quit);
    } else {
        app.quit = true;
    }
}

fn navigate(app: &mut App, down: bool) {
    let settings_len = SETTINGS + app.config.browsers.len();
    let (index, length) = if app.tab <= 1 {
        (&mut app.selected, app.browsers.len())
    } else if app.tab == 5 {
        (&mut app.setting, settings_len)
    } else {
        if down {
            app.scroll = app.scroll.saturating_add(1);
        } else {
            app.scroll = app.scroll.saturating_sub(1);
        }
        return;
    };
    *index = if down {
        index.saturating_add(1).min(length.saturating_sub(1))
    } else {
        index.saturating_sub(1)
    };
}

fn settings_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Enter => app.edit_setting(),
        KeyCode::Char('s') => app.save()?,
        KeyCode::Char('R') => {
            let replacement = App::load()?;
            *app = replacement;
            app.tab = 5;
            app.notice = "Reloaded configuration from disk.".into();
        }
        KeyCode::Char('a') => {
            app.input = Some(Input {
                title: "Custom browser name".into(),
                value: String::new(),
                kind: InputKind::Browser {
                    step: 0,
                    name: String::new(),
                    install: String::new(),
                    editing: None,
                },
            });
        }
        KeyCode::Delete if app.setting >= SETTINGS => {
            app.pending = Some(Pending::RemoveBrowser(app.setting - SETTINGS));
        }
        KeyCode::Char('r') => app.confirm(
            "Restart the registered user daemon? Save Settings first.",
            vec!["daemon".into(), "restart".into()],
            false,
        ),
        KeyCode::Char('g') => app.confirm(
            "Enable automatic startup at login and start the user daemon?",
            vec!["daemon".into(), "enable".into()],
            false,
        ),
        KeyCode::Char('z') => app.confirm(
            "Stop the user daemon and disable automatic startup?",
            vec!["daemon".into(), "disable".into()],
            false,
        ),
        _ => {}
    }
    Ok(())
}

fn confirmation_key(
    app: &mut App,
    key: KeyEvent,
    terminal_state: &mut TerminalState,
) -> Result<()> {
    match key.code {
        KeyCode::Char('y' | 'Y') => match app.pending.take() {
            Some(Pending::Command {
                args, close_after, ..
            }) => {
                app.execute(&args, terminal_state)?;
                if close_after {
                    app.quit = true;
                }
            }
            Some(Pending::RemoveBrowser(index)) if index < app.config.browsers.len() => {
                app.config.browsers.remove(index);
                app.setting = app.setting.saturating_sub(1);
                app.dirty = true;
            }
            Some(Pending::Quit) => app.quit = true,
            _ => {}
        },
        KeyCode::Char('n' | 'N') | KeyCode::Esc => app.pending = None,
        _ => {}
    }
    Ok(())
}

fn input_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => app.input = None,
        KeyCode::Backspace => {
            if let Some(input) = &mut app.input {
                input.value.pop();
            }
        }
        KeyCode::Char(c) if !c.is_control() && !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(input) = &mut app.input {
                if input.value.len() < 4096 {
                    input.value.push(c);
                }
            }
        }
        KeyCode::Enter => {
            if let Some(input) = app.input.take() {
                accept_input(app, input)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn accept_input(app: &mut App, input: Input) -> Result<()> {
    match input.kind {
        InputKind::Search => {
            app.filter = input.value;
            app.scroll = 0;
        }
        InputKind::Export => {
            storage::export(&PathBuf::from(&input.value), &app.report())?;
            app.notice = format!(
                "Saved {}. Reports may include local paths; review before sharing.",
                input.value
            );
        }
        InputKind::Hook(index) => {
            let value = (!input.value.trim().is_empty()).then_some(input.value);
            match index {
                4 => app.config.hooks.pre_patch = value,
                5 => app.config.hooks.post_patch = value,
                _ => app.config.hooks.post_update = value,
            }
            app.dirty = true;
        }
        InputKind::Browser {
            step,
            name,
            install,
            editing,
        } => browser_input(app, step, &name, &install, editing, input.value)?,
    }
    Ok(())
}

fn browser_input(
    app: &mut App,
    step: usize,
    name: &str,
    install: &str,
    editing: Option<usize>,
    value: String,
) -> Result<()> {
    if step == 0 {
        if value.trim().is_empty() {
            return Err(Error::other("Browser name is required"));
        }
        let old = editing.and_then(|i| app.config.browsers.get(i));
        app.input = Some(Input {
            title: "Absolute browser installation path (.app on macOS)".into(),
            value: old
                .and_then(|b| b.bundle_path.as_ref().or(b.install_path.as_ref()))
                .map_or_else(String::new, |p| p.display().to_string()),
            kind: InputKind::Browser {
                step: 1,
                name: value,
                install: String::new(),
                editing,
            },
        });
    } else if step == 1 {
        if !PathBuf::from(&value).is_absolute() {
            return Err(Error::other("Browser installation path must be absolute"));
        }
        if cfg!(windows) {
            let old = editing.and_then(|i| app.config.browsers.get(i));
            app.input = Some(Input {
                title:
                    "Absolute Windows user-data directory (empty uses recognized product default)"
                        .into(),
                value: old
                    .and_then(|b| b.user_data_dir.as_ref())
                    .map_or_else(String::new, |p| p.display().to_string()),
                kind: InputKind::Browser {
                    step: 2,
                    name: name.into(),
                    install: value,
                    editing,
                },
            });
        } else {
            store_browser(app, name, &value, None, editing)?;
        }
    } else {
        let profile = if value.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        };
        store_browser(app, name, install, profile, editing)?;
    }
    Ok(())
}

fn store_browser(
    app: &mut App,
    name: &str,
    install: &str,
    profile: Option<PathBuf>,
    editing: Option<usize>,
) -> Result<()> {
    let framework_name = editing
        .and_then(|index| app.config.browsers.get(index))
        .and_then(|b| b.framework_name.clone());
    let entry = CustomBrowserConfig {
        name: name.into(),
        bundle_path: cfg!(target_os = "macos").then(|| PathBuf::from(install)),
        install_path: (!cfg!(target_os = "macos")).then(|| PathBuf::from(install)),
        framework_name,
        user_data_dir: profile,
    };
    let mut candidate = app.config.clone();
    if let Some(index) = editing {
        candidate.browsers[index] = entry;
    } else {
        candidate.browsers.push(entry);
    }
    Config::from_toml_str(&candidate.to_toml_string()?)?;
    app.config = candidate;
    app.dirty = true;
    app.notice = "Custom browser updated in draft. Press s to save.".into();
    Ok(())
}

fn content(app: &App) -> Vec<String> {
    match app.tab {
        0 | 1 => browser_lines(app),
        2 => app.output.lines().map(str::to_owned).collect(),
        3 => vec![format!("Installed Silvervine: {}", env!("CARGO_PKG_VERSION")), format!("Release channel: {}", app.config.updates.channel.as_str()),
            format!("Automatic self-updates: {}", app.config.updates.auto_apply),
            String::new(), "u  Update Silvervine using saved preferences".into(), "v  Check updater installation (dry run)".into(),
            "w  Update Widevine and patch detected browsers".into(), String::new(),
            "Select Stable or explicitly opt into Preview in Settings.".into(),
            "Preview includes RCs and final releases. Returning to Stable waits for a newer stable version; it does not force a downgrade.".into(),
            "Updating Widevine and updating Silvervine are separate operations.".into()],
        4 => { let mut lines = vec![format!("Filter: {:?} · warnings/errors only: {} · / search · ! severity · b selected browser", app.filter, app.warnings_only)]; lines.extend(app.filtered_logs().lines().map(str::to_owned)); lines },
        _ => { let mut lines = vec![app.config_path.display().to_string(), format!("{} · Enter edit · a add browser · Delete remove · s save · R reload", if app.dirty { "UNSAVED CHANGES" } else { "Saved configuration" }),
            "r restart daemon · g enable startup/start · z disable startup/stop".into(), String::new()];
            lines.extend(app.settings_rows().iter().enumerate().map(|(i, row)| format!("{} {row}", if i == app.setting { ">" } else { " " }))); lines },
    }
}

fn browser_lines(app: &App) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Cached Widevine: {} · Daemon heartbeat: {}",
            app.status.current_cdm_version.as_deref().unwrap_or("none"),
            app.status
                .heartbeat_at
                .map_or_else(|| "unavailable".into(), |t| t.to_string())
        ),
        String::new(),
        "p patch · l launch · t browser test · d passive diagnostics · i setup".into(),
        String::new(),
    ];
    for (index, browser) in app.status.browsers.iter().enumerate() {
        lines.push(format!(
            "{} {:<24} {:<10} CDM {}",
            if index == app.selected { ">" } else { " " },
            browser.name,
            if browser.patched {
                "patched"
            } else {
                "unpatched"
            },
            browser.cdm_version.as_deref().unwrap_or("none")
        ));
        if app.tab == 1 && index == app.selected {
            lines.push(format!("    {}", browser.install_path));
        }
    }
    if app.browsers.is_empty() {
        lines.push(
            "No browsers detected. Press i for setup, or add an installation path in Settings."
                .into(),
        );
    }
    lines
}

fn draw(app: &App) -> Result<()> {
    let (cols, rows) = terminal::size()?;
    let width = cols as usize;
    let height = rows.saturating_sub(5) as usize;
    let mut out = io::stdout().lock();
    crossterm::queue!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::All)
    )?;
    let header = format!(
        "Silvervine {}  |  {}",
        env!("CARGO_PKG_VERSION"),
        TABS.iter()
            .enumerate()
            .map(|(i, t)| if i == app.tab {
                format!("[{} {t}]", i + 1)
            } else {
                format!("{} {t}", i + 1)
            })
            .collect::<Vec<_>>()
            .join("  ")
    );
    write!(out, "{}\r\n\r\n", storage::visible_line(&header, width))?;
    let lines = content(app);
    let start = if app.tab <= 1 {
        app.selected.saturating_sub(height.saturating_sub(5))
    } else if app.tab == 5 {
        app.setting.saturating_sub(height.saturating_sub(5))
    } else {
        app.scroll.min(lines.len().saturating_sub(height))
    };
    for line in lines.iter().skip(start).take(height) {
        write!(out, "{}\r\n", storage::visible_line(line, width))?;
    }
    if rows >= 3 {
        crossterm::queue!(out, cursor::MoveTo(0, rows - 3))?;
    }
    let prompt = if let Some(input) = &app.input {
        format!(
            "{} · Enter accept · Esc cancel\r\n> {}",
            input.title, input.value
        )
    } else if let Some(pending) = &app.pending {
        let label = match pending {
            Pending::Command { label, .. } => label.as_str(),
            Pending::RemoveBrowser(_) => {
                "Remove this custom configuration entry? The browser itself will remain installed."
            }
            Pending::Quit => "Discard unsaved settings and quit?",
        };
        format!("{label}\r\ny confirm · n/Esc cancel")
    } else {
        app.notice.clone()
    };
    for line in prompt.lines().take(3) {
        write!(out, "{}\r\n", storage::visible_line(line, width))?;
    }
    out.flush()?;
    Ok(())
}
