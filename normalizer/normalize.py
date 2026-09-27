#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Triage Collector Kit - normalizer (v0.2.0)

Converts Windows collector output (CSV) into a unified NDJSON schema.
Standard library only. Missing or empty files are skipped gracefully.

Usage:
    python normalize.py --input ./Triage_HOST_TS [--output events.ndjson]
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

# --- Constants ---------------------------------------------------------------

DATE_FORMATS = (
    "%d.%m.%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d.%m.%Y %H:%M",
)

SYSTEM_OWNERS = {"system", "система", "nt authority\\system", "local system", "localsystem"}

SCRIPT_INTERPRETERS = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}

HACKTOOL_KEYWORDS = ("kmsauto", "kmspico", "activator", "crack", "keygen")

TEMP_MARKERS = ("\\temp\\", "/tmp/", "/dev/shm", "\\appdata\\local\\temp", "\\public\\")

WINDOWS_ROOT_RE = re.compile(r"(^|[^\\])c:\\windows\\[^\\]+\.exe|%windir%\\[^\\]+\.exe", re.I)

ENCODED_RE = re.compile(r"-enc(odedcommand)?\s|frombase64string", re.I)


def parse_dt(raw):
    if not raw:
        return None
    raw = raw.strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    return None


def ip_is_local(raw):
    try:
        addr = ip_address(raw)
    except ValueError:
        return True
    return addr.is_loopback or addr.is_private or addr.is_multicast \
        or addr.is_reserved or addr.is_unspecified


def read_csv(path: Path):
    if not path.is_file():
        return []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return [row for row in csv.DictReader(fh)]
    except Exception as exc:
        print(f"[warn] cannot read {path.name}: {exc}", file=sys.stderr)
        return []


def case_meta(input_dir: Path):
    name = input_dir.name
    m = re.match(r"(?i)^triage_(.+)_(\d{8})_(\d{6})$", name)
    if m:
        host, d, t = m.groups()
        collected = f"{d[0:4]}-{d[4:6]}-{d[6:8]}T{t[0:2]}:{t[2:4]}:{t[4:6]}"
    else:
        host, collected = name, None
    return {"case_id": name, "hostname": host, "collected_at": collected}


class Normalizer:
    def __init__(self, input_dir: Path):
        self.input = input_dir
        self.meta = case_meta(input_dir)
        self.events = []
        self.stats = {}

    def emit(self, artifact_type, event_time, data, tags):
        self.events.append({
            "case_id": self.meta["case_id"],
            "hostname": self.meta["hostname"],
            "os": "windows",
            "collector": "windows_triage",
            "collected_at": self.meta["collected_at"],
            "artifact_type": artifact_type,
            "event_time": event_time,
            "data": data,
            "tags": tags,
        })

    def processes(self):
        rows = read_csv(self.input / "01_Processes.csv")
        pid2name = {r.get("ProcessId"): (r.get("Name") or "").lower() for r in rows}

        for r in rows:
            tags = []
            name = (r.get("Name") or "").strip()
            path = (r.get("ExecutablePath") or "").strip()
            cmd = (r.get("CommandLine") or "").strip()
            owner = (r.get("Owner") or "").strip()
            blob = (path + " " + cmd).lower()

            if any(m in blob for m in TEMP_MARKERS):
                tags.append("temp_execution")
            if not path and name:
                tags.append("missing_image_path")
            if WINDOWS_ROOT_RE.search(path) or WINDOWS_ROOT_RE.search(cmd):
                tags.append("binary_in_windows_root")
            if name.lower() in SCRIPT_INTERPRETERS:
                tags.append("script_interpreter")
            if ENCODED_RE.search(cmd):
                tags.append("encoded_command")
            if any(k in name.lower() for k in HACKTOOL_KEYWORDS):
                tags.append("known_hacktool_name")

            parent_name = pid2name.get(r.get("ParentProcessId"), "")
            if parent_name in OFFICE_PARENTS:
                tags.append("office_parent")
            if owner.lower() in SYSTEM_OWNERS:
                tags.append("runs_as_system")

            self.emit("process", parse_dt(r.get("CreationDate")), {
                "pid": r.get("ProcessId"),
                "ppid": r.get("ParentProcessId"),
                "parent_name": parent_name,
                "name": name,
                "path": path,
                "command": cmd,
                "owner": owner,
            }, tags)
        self.stats["process"] = len(rows)

    def network(self):
        rows = read_csv(self.input / "02_NetworkConnections.csv")
        for r in rows:
            tags = []
            state = (r.get("State") or "").strip().lower()
            laddr = (r.get("LocalAddress") or "").strip()
            raddr = (r.get("RemoteAddress") or "").strip()

            if state == "listen" and laddr in ("::", "0.0.0.0"):
                tags.append("listening_all_interfaces")
            if state == "established" and raddr and not ip_is_local(raddr):
                tags.append("external_connection")

            self.emit("network", None, {
                "local_address": laddr,
                "local_port": r.get("LocalPort"),
                "remote_address": raddr,
                "remote_port": r.get("RemotePort"),
                "state": (r.get("State") or "").strip(),
                "pid": r.get("OwningProcess"),
                "process_name": (r.get("ProcessName") or "").strip(),
            }, tags)
        self.stats["network"] = len(rows)

    def services(self):
        rows = read_csv(self.input / "03_Services_Auto.csv")
        for r in rows:
            tags = []
            p = (r.get("PathName") or "").strip()
            low = p.lower()

            if any(m in low for m in TEMP_MARKERS):
                tags.append("temp_execution")
            if WINDOWS_ROOT_RE.search(p):
                tags.append("binary_in_windows_root")
            if any(k in low for k in HACKTOOL_KEYWORDS):
                tags.append("known_hacktool_name")
            if (r.get("StartName") or "").strip().lower() in SYSTEM_OWNERS:
                tags.append("runs_as_system")

            self.emit("service", None, {
                "name": (r.get("Name") or "").strip(),
                "display_name": (r.get("DisplayName") or "").strip(),
                "state": (r.get("State") or "").strip(),
                "start_name": (r.get("StartName") or "").strip(),
                "path": p,
            }, tags)
        self.stats["service"] = len(rows)

    def tasks(self):
        rows = read_csv(self.input / "04_ScheduledTasks.csv")
        for r in rows:
            tags = []
            name = (r.get("TaskName") or "").strip()
            actions = (r.get("Actions") or "").strip()
            blob = (name + " " + actions).lower()

            if any(k in blob for k in HACKTOOL_KEYWORDS):
                tags.append("known_hacktool_name")
            if WINDOWS_ROOT_RE.search(actions):
                tags.append("binary_in_windows_root")
            if any(m in blob for m in TEMP_MARKERS):
                tags.append("temp_execution")

            self.emit("task", None, {
                "name": name,
                "path": (r.get("TaskPath") or "").strip(),
                "state": (r.get("State") or "").strip(),
                "actions": actions,
            }, tags)
        self.stats["task"] = len(rows)

    def users(self):
        rows = read_csv(self.input / "05_LocalAdmins.csv")
        for r in rows:
            self.emit("user", None, {
                "name": (r.get("Name") or "").strip(),
                "source": (r.get("PrincipalSource") or "").strip(),
                "class": (r.get("ObjectClass") or "").strip(),
            }, [])
        self.stats["user"] = len(rows)

    def run(self):
        self.processes()
        self.network()
        self.services()
        self.tasks()
        self.users()


def main():
    ap = argparse.ArgumentParser(
        description="Normalize Triage Collector Kit output into NDJSON")
    ap.add_argument("--input", required=True, type=Path,
                    help="path to a Triage_* folder")
    ap.add_argument("--output", type=Path, default=None,
                    help="output .ndjson file (default: <case_id>.events.ndjson)")
    args = ap.parse_args()

    inp = args.input
    if not inp.is_dir():
        sys.exit(f"input dir not found: {inp}")

    if (inp / "01_Processes.csv").is_file():
        pass
    elif (inp / "01_processes").is_dir():
        sys.exit("Unix triage detected. Unix parsers land in v0.2.1; "
                 "v0.2.0 parses Windows CSV output only.")
    else:
        sys.exit("Neither Windows nor Unix triage structure found in: " + str(inp))

    nz = Normalizer(inp)
    nz.run()

    out = args.output or Path(f"{nz.meta['case_id']}.events.ndjson")
    with open(out, "w", encoding="utf-8") as fh:
        for ev in nz.events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"case:   {nz.meta['case_id']}")
    print(f"events: {len(nz.events)} -> {out}")
    for key in ("process", "network", "service", "task", "user"):
        print(f"  {key:8s}: {nz.stats.get(key, 0)}")

    tagged = [e for e in nz.events if e["tags"]]
    print(f"tagged: {len(tagged)}")
    for e in tagged[:15]:
        preview = json.dumps(e["data"], ensure_ascii=False)[:110]
        print(f"  [{e['artifact_type']}] {','.join(e['tags'])} :: {preview}")


if __name__ == "__main__":
    main()
