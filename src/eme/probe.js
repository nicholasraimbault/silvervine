(() => {
  "use strict";

  const KEY_SYSTEM = "com.widevine.alpha";
  const ROBUSTNESS = [
    "SW_SECURE_CRYPTO",
    "SW_SECURE_DECODE",
    "HW_SECURE_CRYPTO",
    "HW_SECURE_DECODE",
    "HW_SECURE_ALL",
  ];
  const SCHEMES = ["cenc", "cbcs"];
  const HDCP = ["1.4", "2.2"];
  const VIDEO_CODECS = [
    { codec: "avc1.640028", content_type: 'video/mp4; codecs="avc1.640028"' },
    { codec: "hvc1.1.6.L120.B0", content_type: 'video/mp4; codecs="hvc1.1.6.L120.B0"' },
    { codec: "vp09.00.51.08", content_type: 'video/webm; codecs="vp09.00.51.08"' },
    { codec: "av01.0.08M.08", content_type: 'video/mp4; codecs="av01.0.08M.08"' },
  ];
  const SIZES = [
    { width: 1280, height: 720, framerate: 30, bitrate: 4_000_000 },
    { width: 1920, height: 1080, framerate: 30, bitrate: 8_000_000 },
    { width: 3840, height: 2160, framerate: 30, bitrate: 20_000_000 },
  ];
  const AUDIO = {
    codec: "mp4a.40.2",
    content_type: 'audio/mp4; codecs="mp4a.40.2"',
  };

  const statusEl = () => document.getElementById("status");
  const summaryEl = () => document.getElementById("summary");
  const findingsEl = () => document.getElementById("findings");
  const actionsEl = () => document.getElementById("actions");
  const limitsEl = () => document.getElementById("limits");

  const detail = (error) => {
    const name = typeof error?.name === "string" ? error.name : "Error";
    const message = typeof error?.message === "string" ? error.message : String(error);
    return `${name}: ${message}`.slice(0, 240);
  };

  const setStatus = (phase, text) => {
    const node = statusEl();
    if (!node) return;
    node.dataset.phase = phase;
    node.textContent = text;
  };

  const listReplace = (element, items, emptyText) => {
    if (!element) return;
    element.replaceChildren();
    if (!items || items.length === 0) {
      const li = document.createElement("li");
      li.textContent = emptyText;
      element.appendChild(li);
      return;
    }
    for (const item of items) {
      const li = document.createElement("li");
      li.textContent = item;
      element.appendChild(li);
    }
  };

  const renderAssessment = (assessment) => {
    setStatus(
      assessment.status === "pass" ? "completed" : "error",
      assessment.status === "pass"
        ? "Capability check complete."
        : `Capability check finished: ${assessment.status}.`,
    );
    if (summaryEl()) {
      summaryEl().textContent = assessment.summary || "No summary returned.";
    }
    listReplace(findingsEl(), assessment.findings || [], "No findings.");
    listReplace(actionsEl(), assessment.actions || [], "No actions.");
    listReplace(
      limitsEl(),
      assessment.service_limits || [],
      "Service policy and entitlement remain untested.",
    );
  };

  // Temporary sessions only. Never request long-lived sessions or required identifiers.
  const config = ({ mediaKind, contentType, robustness = "", encryptionScheme }) => {
    const capability = { contentType };
    if (robustness) capability.robustness = robustness;
    if (encryptionScheme) capability.encryptionScheme = encryptionScheme;
    return {
      initDataTypes: ["cenc"],
      distinctiveIdentifier: "not-allowed",
      persistentState: "not-allowed",
      sessionTypes: ["temporary"],
      [`${mediaKind}Capabilities`]: [capability],
    };
  };

  const requestAccess = async (configuration) => {
    if (typeof navigator.requestMediaKeySystemAccess !== "function") {
      return {
        status: "unavailable",
        detail: "requestMediaKeySystemAccess is unavailable",
      };
    }
    try {
      const access = await navigator.requestMediaKeySystemAccess(KEY_SYSTEM, [configuration]);
      return { status: "supported", access };
    } catch (error) {
      const rejected = error?.name === "NotSupportedError";
      return {
        status: rejected ? "rejected" : "error",
        detail: detail(error),
      };
    }
  };

  const probeRobustness = async () => {
    const results = [];
    for (const mediaKind of ["audio", "video"]) {
      const contentType =
        mediaKind === "audio" ? AUDIO.content_type : VIDEO_CODECS[0].content_type;
      for (const robustness of ROBUSTNESS) {
        const request = await requestAccess(
          config({ mediaKind, contentType, robustness }),
        );
        results.push({
          media_kind: mediaKind,
          robustness,
          accepted: request.status === "supported",
          ...(request.detail ? { error: request.detail } : {}),
        });
      }
    }
    return results;
  };

  const probeSchemes = async () => {
    const results = [];
    for (const scheme of SCHEMES) {
      const request = await requestAccess(
        config({
          mediaKind: "video",
          contentType: VIDEO_CODECS[0].content_type,
          encryptionScheme: scheme,
        }),
      );
      results.push({
        scheme,
        accepted: request.status === "supported",
        ...(request.detail ? { error: request.detail } : {}),
      });
    }
    return results;
  };

  const canPlay = (contentType) => {
    try {
      const video = document.createElement("video");
      return String(video.canPlayType(contentType) || "");
    } catch (_error) {
      return "";
    }
  };

  const mseSupported = (contentType) => {
    try {
      return typeof MediaSource !== "undefined" && MediaSource.isTypeSupported(contentType);
    } catch (_error) {
      return false;
    }
  };

  const probeCodecConfig = async ({ codec, content_type: contentType }, size) => {
    const base = {
      codec,
      content_type: contentType,
      width: size.width,
      height: size.height,
      framerate: size.framerate,
      mse_supported: mseSupported(contentType),
      direct_playback: canPlay(contentType),
    };
    if (typeof navigator.mediaCapabilities?.decodingInfo !== "function") {
      return {
        ...base,
        error: "MediaCapabilities.decodingInfo is unavailable",
      };
    }
    try {
      const result = await navigator.mediaCapabilities.decodingInfo({
        type: "media-source",
        video: {
          contentType,
          width: size.width,
          height: size.height,
          bitrate: size.bitrate,
          framerate: size.framerate,
        },
        keySystemConfiguration: {
          keySystem: KEY_SYSTEM,
          initDataType: "cenc",
          distinctiveIdentifier: "not-allowed",
          persistentState: "not-allowed",
          sessionTypes: ["temporary"],
          video: { contentType, robustness: "" },
        },
      });
      const mc = {
        supported: !!result.supported,
        smooth: typeof result.smooth === "boolean" ? result.smooth : null,
        power_efficient:
          typeof result.powerEfficient === "boolean" ? result.powerEfficient : null,
      };
      // Record only what MediaCapabilities actually returned for key-system access.
      if (result.keySystemAccess === true) {
        mc.key_system_access = true;
      } else if (result.keySystemAccess && typeof result.keySystemAccess === "object") {
        mc.key_system_access = true;
      } else if (result.keySystemAccess === false) {
        mc.key_system_access = false;
      }
      // null/undefined: omit key_system_access entirely.
      return {
        ...base,
        media_capabilities: mc,
      };
    } catch (error) {
      return {
        ...base,
        error: detail(error),
      };
    }
  };

  const probeCodecs = async () => {
    const codecs = [];
    for (const codec of VIDEO_CODECS) {
      for (const size of SIZES) {
        codecs.push(await probeCodecConfig(codec, size));
      }
    }
    return codecs;
  };

  const probeHdcp = async (baselineAccess) => {
    if (!baselineAccess) {
      return HDCP.map((min_version) => ({
        min_version,
        error: "Widevine key-system access was unavailable",
      }));
    }
    try {
      const mediaKeys = await baselineAccess.createMediaKeys();
      if (typeof mediaKeys.getStatusForPolicy !== "function") {
        return HDCP.map((min_version) => ({
          min_version,
          error: "MediaKeys.getStatusForPolicy is unavailable",
        }));
      }
      const results = [];
      for (const min_version of HDCP) {
        try {
          const status = await mediaKeys.getStatusForPolicy({
            minHdcpVersion: min_version,
          });
          results.push({
            min_version,
            status: String(status),
          });
        } catch (error) {
          results.push({
            min_version,
            error: detail(error),
          });
        }
      }
      return results;
    } catch (error) {
      return HDCP.map((min_version) => ({
        min_version,
        error: detail(error),
      }));
    }
  };

  const main = async () => {
    setStatus("running", "Checking browser media capabilities…");
    const emeApi = typeof navigator.requestMediaKeySystemAccess === "function";
    const mediaCapabilitiesApi =
      typeof navigator.mediaCapabilities?.decodingInfo === "function";

    const baseline = await requestAccess(
      config({
        mediaKind: "video",
        contentType: VIDEO_CODECS[0].content_type,
      }),
    );

    const result = {
      schema_version: 1,
      user_agent: String(navigator.userAgent || "unknown").slice(0, 512),
      eme_api: emeApi,
      media_capabilities_api: mediaCapabilitiesApi,
      baseline: baseline.status,
      ...(baseline.detail ? { baseline_error: baseline.detail } : {}),
      robustness: await probeRobustness(),
      encryption_schemes: await probeSchemes(),
      hdcp: await probeHdcp(baseline.access),
      codecs: await probeCodecs(),
    };

    const response = await fetch("result", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(result),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) {
      throw new Error(`Silvervine probe upload failed: HTTP ${response.status}`);
    }
    const assessment = await response.json();
    renderAssessment(assessment);
  };

  main().catch((error) => {
    setStatus("error", `Capability check failed: ${detail(error)}.`);
    if (summaryEl()) {
      summaryEl().textContent =
        "Return to the Silvervine terminal for the categorized error.";
    }
  });
})();
