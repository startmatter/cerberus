/** cerberus.yml loading with full defaults — a missing file is valid config. */

import { readFileSync } from "node:fs";
import { parse } from "yaml";
import type { CerberusConfig, CustomScanner, GatePolicy, UploadMode } from "./types.js";

const GATE_POLICIES: GatePolicy[] = ["new-critical", "new-high", "any-new", "never"];
const UPLOAD_MODES: UploadMode[] = ["auto", "report", "check", "off"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}

function oneOf<T extends string>(v: unknown, allowed: T[], fallback: T, label: string): T {
  if (v === undefined) return fallback;
  if (typeof v === "string" && (allowed as string[]).includes(v)) return v as T;
  throw new Error(`Invalid ${label}: "${String(v)}" (expected one of ${allowed.join(", ")})`);
}

export function parseConfig(raw: unknown): CerberusConfig {
  const root = isRecord(raw) ? raw : {};
  const scanners = isRecord(root.scanners) ? root.scanners : {};
  const gate = isRecord(root.gate) ? root.gate : {};
  const upload = isRecord(root.upload) ? root.upload : {};

  const scanner = (key: string) => (isRecord(scanners[key]) ? (scanners[key] as Record<string, unknown>) : {});
  const enabled = (s: Record<string, unknown>) => s.enabled !== false; // default on

  const semgrep = scanner("semgrep");
  const gitleaks = scanner("gitleaks");
  const trivy = scanner("trivy");

  const custom: CustomScanner[] = [];
  for (const entry of Array.isArray(scanners.custom) ? scanners.custom : []) {
    if (!isRecord(entry)) continue;
    const name = typeof entry.name === "string" ? entry.name.trim() : "";
    const command = typeof entry.command === "string" ? entry.command.trim() : "";
    if (!name || !command) throw new Error("Custom scanners need both `name` and `command`");
    if (!command.includes("{output}")) throw new Error(`Custom scanner "${name}": command must contain {output}`);
    custom.push({ name, command });
  }

  return {
    scanners: {
      semgrep: {
        enabled: enabled(semgrep),
        config: typeof semgrep.config === "string" && semgrep.config ? semgrep.config : "p/security-audit",
        args: strArray(semgrep.args),
      },
      gitleaks: { enabled: enabled(gitleaks), args: strArray(gitleaks.args) },
      trivy: {
        enabled: enabled(trivy),
        scanners: strArray(trivy.scanners).length ? strArray(trivy.scanners) : ["vuln", "secret", "misconfig"],
        args: strArray(trivy.args),
      },
      custom,
    },
    gate: { failOn: oneOf(gate.fail_on, GATE_POLICIES, "new-critical", "gate.fail_on") },
    upload: {
      mode: oneOf(upload.mode, UPLOAD_MODES, "auto", "upload.mode"),
      partial: upload.partial === true,
    },
  };
}

/** Load `cerberus.yml` from the scan root; absent file = defaults. */
export function loadConfig(path: string): CerberusConfig {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return parseConfig({});
  }
  return parseConfig(parse(text));
}
