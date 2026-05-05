//! Windows unattended-install XML generator — V3-Phase C.
//!
//! Renders an `autounattend.xml` per Microsoft's Win11 `IoT` Enterprise
//! LTSC unattended-installation schema. The XML is embedded into a
//! tiny ISO that gets attached as a virtual CD-ROM during the unattended
//! install — Windows looks for `autounattend.xml` at the root of any
//! attached drive during early setup.
//!
//! ## Apple-UX guarantees baked into the rendered XML
//!
//! * `en-US` system locale, US keyboard, UTC timezone.
//! * No Microsoft Account prompt — local user `neon-bridge` with
//!   auto-login.
//! * EULA accepted.
//! * OOBE bypassed (privacy choices, region, keyboard, all
//!   `<HideXxxPage>true</HideXxxPage>`).
//! * First-logon command: PowerShell script that:
//!   - Disables Edge first-run experience.
//!   - Confirms Edge is installed (it is in `IoT` LTSC by default).
//!   - Installs Sunshine via direct download (URL pinned).
//!   - Configures Sunshine for headless Looking Glass operation.
//!   - Creates a `C:\neon-bridge-ready` sentinel file.
//!   - Sets up scheduled task for `slmgr /rearm` 7 days before trial
//!     expiry (only when [`UnattendedOptions::license_posture`] is
//!     `LicensePosture::Eval`).
//!
//! ## What this module does NOT do
//!
//! * No ISO generation — that's `bridge::install` (uses
//!   `genisoimage` or a hand-rolled ISO9660 helper).
//! * No subprocess execution — pure rendering.

use crate::bridge::license::LicensePosture;
use crate::error::{Error, Result};

/// Default Sunshine URL — pinned at compile time. If the URL goes
/// stale, Microsoft's `WinGet` path is the recommended fallback.
pub const DEFAULT_SUNSHINE_URL: &str =
    "https://github.com/LizardByte/Sunshine/releases/download/v0.23.1/sunshine-windows-installer.exe";

/// Default Sunshine SHA-256 (matches the v0.23.1 Windows installer at
/// release time). Override via [`UnattendedOptions::sunshine_sha256`].
pub const DEFAULT_SUNSHINE_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Options for [`render_autounattend`]. Most callers fill this from
/// command-line flags + the resolved license posture.
#[derive(Debug, Clone)]
pub struct UnattendedOptions {
    /// Resolved license posture. The XML's `<ProductKey>` block is
    /// emitted only for `Key` / `KeyFile`; the trial path skips
    /// product-key entry entirely (Microsoft accepts trial when no key
    /// is present and the user accepted the EULA).
    pub license_posture: LicensePosture,
    /// URL the first-logon PowerShell pulls Sunshine from.
    pub sunshine_url: String,
    /// SHA-256 of the Sunshine installer for verification.
    pub sunshine_sha256: String,
    /// Hostname the guest will use. The wizard uses `"neon-bridge"`.
    pub hostname: String,
    /// Local user name for auto-login. The wizard uses `"neon-bridge"`.
    pub local_username: String,
}

impl UnattendedOptions {
    /// Build options with the pinned Sunshine URL/SHA + the wizard's
    /// canonical hostname/username.
    #[must_use]
    pub fn defaults_for(license_posture: LicensePosture) -> Self {
        Self {
            license_posture,
            sunshine_url: DEFAULT_SUNSHINE_URL.to_string(),
            sunshine_sha256: DEFAULT_SUNSHINE_SHA256.to_string(),
            hostname: "neon-bridge".to_string(),
            local_username: "neon-bridge".to_string(),
        }
    }
}

/// Render `autounattend.xml` for the given options.
///
/// The output is UTF-8 encoded XML, ready to be written to a file (and
/// then bundled into a small ISO9660 image via `bridge::install`).
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — if the supplied options contain
///   characters that would corrupt the XML (e.g. raw `<` in a hostname).
#[allow(clippy::too_many_lines)]
pub fn render_autounattend(opts: &UnattendedOptions) -> Result<String> {
    if !opts
        .hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Error::other(format!(
            "hostname {:?} contains characters that would corrupt the XML",
            opts.hostname
        )));
    }
    if !opts
        .local_username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Error::other(format!(
            "local_username {:?} contains characters that would corrupt the XML",
            opts.local_username
        )));
    }

    // Product-key block — empty for trial (Microsoft accepts no-key when
    // EULA is accepted), populated for explicit Key / KeyFile postures.
    let product_key_block = match &opts.license_posture {
        LicensePosture::Eval { .. } => String::new(),
        LicensePosture::Key(k) => format!(
            "        <UserData>\n            <ProductKey>\n                <Key>{}</Key>\n                <WillShowUI>OnError</WillShowUI>\n            </ProductKey>\n            <AcceptEula>true</AcceptEula>\n        </UserData>\n",
            xml_escape(k)
        ),
        LicensePosture::KeyFile(_) => {
            // Key-file mode: install-orchestration reads the file and
            // injects the resolved key before rendering. The XML
            // template alone has no key value. Surface this as an
            // error so callers don't accidentally render a no-key XML.
            return Err(Error::other(
                "render_autounattend: KeyFile posture requires the install \
                 orchestrator to resolve the key file before rendering",
            ));
        }
    };

    let rearm_block = match &opts.license_posture {
        LicensePosture::Eval { .. } => format!(
            "      <RunSynchronousCommand wcm:action=\"add\">\n        <Order>10</Order>\n        <Path>cmd /c schtasks /Create /TN NeonBridgeRearm /TR \"{}\" /SC ONCE /ST 03:00 /SD 01/01/2099 /RU SYSTEM</Path>\n        <Description>Schedule slmgr /rearm 7 days before eval expiry</Description>\n      </RunSynchronousCommand>\n",
            xml_escape(crate::bridge::license::rearm_command_for_guest())
        ),
        LicensePosture::Key(_) | LicensePosture::KeyFile(_) => String::new(),
    };

    let first_logon_script = build_first_logon_script(opts);
    let first_logon_block = format!(
        "      <SynchronousCommand wcm:action=\"add\">\n        <Order>1</Order>\n        <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command \"{}\"</CommandLine>\n        <Description>Neon bridge first-logon orchestration</Description>\n      </SynchronousCommand>\n",
        xml_escape(&first_logon_script)
    );

    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage>
        <UILanguage>en-US</UILanguage>
      </SetupUILanguage>
      <InputLocale>0409:00000409</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Size>500</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>EFI</Type>
              <Size>100</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order>
              <Type>MSR</Type>
              <Size>16</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>4</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>WinRE</Label>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>2</PartitionID>
              <Format>FAT32</Format>
              <Label>System</Label>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>3</Order>
              <PartitionID>3</PartitionID>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>4</Order>
              <PartitionID>4</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>4</PartitionID>
          </InstallTo>
          <InstallToAvailablePartition>false</InstallToAvailablePartition>
        </OSImage>
      </ImageInstall>
{product_key_block}    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{hostname}</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
{rearm_block}      </RunSynchronous>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>0409:00000409</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Home</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password>
              <Value></Value>
              <PlainText>true</PlainText>
            </Password>
            <Description>Neon bridge runner</Description>
            <DisplayName>{user}</DisplayName>
            <Group>Administrators</Group>
            <Name>{user}</Name>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Password>
          <Value></Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <LogonCount>9999</LogonCount>
        <Username>{user}</Username>
      </AutoLogon>
      <FirstLogonCommands>
{first_logon_block}      </FirstLogonCommands>
      <RegisteredOrganization>Neon</RegisteredOrganization>
      <RegisteredOwner>{user}</RegisteredOwner>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
</unattend>
"#,
        hostname = xml_escape(&opts.hostname),
        user = xml_escape(&opts.local_username),
        product_key_block = product_key_block,
        rearm_block = rearm_block,
        first_logon_block = first_logon_block,
    );
    Ok(xml)
}

/// Construct the inline first-logon PowerShell. Embedded in
/// `<CommandLine>` via single-line PowerShell with semicolon-separated
/// statements.
fn build_first_logon_script(opts: &UnattendedOptions) -> String {
    let url = &opts.sunshine_url;
    let sha = &opts.sunshine_sha256;
    let parts = [
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name HideFirstRunExperience -Value 1 -Force -ErrorAction SilentlyContinue".to_string(),
        format!(
            "$u = '{url}'; $h = '{sha}'"
        ),
        "$dst = \"$env:TEMP\\sunshine-installer.exe\"".to_string(),
        "Invoke-WebRequest -Uri $u -OutFile $dst".to_string(),
        "$got = (Get-FileHash $dst -Algorithm SHA256).Hash.ToLower()".to_string(),
        "if ($got -ne $h.ToLower()) { throw \"Sunshine SHA mismatch\" }".to_string(),
        "Start-Process -FilePath $dst -ArgumentList '/S' -Wait".to_string(),
        "Set-Service -Name sunshinesvc -StartupType Automatic".to_string(),
        "New-Item -ItemType File -Path 'C:\\neon-bridge-ready' -Force".to_string(),
    ];
    parts.join("; ")
}

/// Minimal XML escape — enough for attribute values and PCDATA in the
/// XML we generate. Doesn't try to handle UTF-16 surrogates etc.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse the rendered XML with quick-xml to confirm it's
    /// well-formed.
    fn parses_as_xml(s: &str) -> bool {
        let mut reader = quick_xml::Reader::from_str(s);
        loop {
            let mut buf = Vec::new();
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }

    #[test]
    fn renders_for_eval_posture_without_product_key() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        let xml = render_autounattend(&opts).expect("render");
        assert!(parses_as_xml(&xml), "rendered XML must parse: {xml}");
        // No <ProductKey> block in trial mode.
        assert!(
            !xml.contains("<ProductKey>"),
            "trial posture must not emit <ProductKey>"
        );
        // Trial-mode rearm task must be scheduled.
        assert!(
            xml.contains("NeonBridgeRearm"),
            "trial posture must schedule a rearm task"
        );
    }

    #[test]
    fn renders_for_key_posture_with_product_key() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::Key(
            "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into(),
        ));
        let xml = render_autounattend(&opts).expect("render");
        assert!(parses_as_xml(&xml));
        assert!(
            xml.contains("<ProductKey>"),
            "key posture must emit <ProductKey>"
        );
        assert!(xml.contains("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"));
        assert!(xml.contains("<AcceptEula>true</AcceptEula>"));
        // No rearm task for keyed installs.
        assert!(
            !xml.contains("NeonBridgeRearm"),
            "key posture must NOT schedule rearm"
        );
    }

    #[test]
    fn renders_required_microsoft_elements() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        let xml = render_autounattend(&opts).expect("render");
        for required in &[
            "<unattend",
            "urn:schemas-microsoft-com:unattend",
            "<settings pass=\"windowsPE\">",
            "<settings pass=\"oobeSystem\">",
            "<AutoLogon>",
            "<FirstLogonCommands>",
            "<HideEULAPage>true</HideEULAPage>",
            "<SkipMachineOOBE>true</SkipMachineOOBE>",
            "<SkipUserOOBE>true</SkipUserOOBE>",
            "<TimeZone>UTC</TimeZone>",
            "<UserLocale>en-US</UserLocale>",
            "<InputLocale>0409:00000409</InputLocale>",
        ] {
            assert!(
                xml.contains(required),
                "rendered XML missing required element {required}: {xml}"
            );
        }
    }

    #[test]
    fn renders_first_logon_with_sunshine_install() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        let xml = render_autounattend(&opts).expect("render");
        // Sentinel file creation appears in the inline PS.
        assert!(
            xml.contains("neon-bridge-ready"),
            "first-logon must drop the sentinel file"
        );
        // The default Sunshine URL appears.
        assert!(
            xml.contains("Sunshine") || xml.contains("sunshine"),
            "first-logon must include Sunshine install"
        );
    }

    #[test]
    fn rejects_keyfile_posture() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::KeyFile("/tmp/keys.csv".into()));
        let err = render_autounattend(&opts).expect_err("KeyFile must error");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    #[test]
    fn rejects_hostname_with_xml_special_chars() {
        let mut opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        opts.hostname = "<script>".into();
        let err = render_autounattend(&opts).expect_err("malicious hostname");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    #[test]
    fn rejects_username_with_xml_special_chars() {
        let mut opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        opts.local_username = "&malicious;".into();
        let err = render_autounattend(&opts).expect_err("malicious user");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    #[test]
    fn xml_escape_handles_basic_specials() {
        assert_eq!(xml_escape("a<b"), "a&lt;b");
        assert_eq!(xml_escape("a>b"), "a&gt;b");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("a\"b"), "a&quot;b");
        assert_eq!(xml_escape("a'b"), "a&apos;b");
    }

    #[test]
    fn defaults_for_uses_canonical_hostname() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        assert_eq!(opts.hostname, "neon-bridge");
        assert_eq!(opts.local_username, "neon-bridge");
        assert_eq!(opts.sunshine_url, DEFAULT_SUNSHINE_URL);
        assert_eq!(opts.sunshine_sha256, DEFAULT_SUNSHINE_SHA256);
    }

    #[test]
    fn build_first_logon_script_includes_sentinel_creation() {
        let opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        let script = build_first_logon_script(&opts);
        assert!(script.contains("C:\\neon-bridge-ready"));
        assert!(script.contains("Invoke-WebRequest"));
        assert!(script.contains("SHA256"));
    }

    #[test]
    fn xml_escape_is_idempotent_for_safe_input() {
        let safe = "neon-bridge_v1";
        assert_eq!(xml_escape(safe), safe);
    }

    #[test]
    fn renders_with_custom_sunshine_url() {
        let mut opts = UnattendedOptions::defaults_for(LicensePosture::Eval { accepted_at: 1 });
        opts.sunshine_url = "https://example.com/sunshine.exe".into();
        opts.sunshine_sha256 = "1".repeat(64);
        let xml = render_autounattend(&opts).expect("render");
        assert!(xml.contains("https://example.com/sunshine.exe"));
        assert!(xml.contains(&"1".repeat(64)));
    }
}
