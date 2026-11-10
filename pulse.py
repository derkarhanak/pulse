#!/usr/bin/env python3
"""Pulse — a calm, easy-to-read system monitor for GNOME."""

import os
import re
import signal
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

import psutil  # noqa: E402

APP_ID = "io.github.samsyk.Pulse"
INTERVAL = 2.0
HISTORY = 60
ROW_LIMIT = 12

COLORS = {
    "cpu": "#3584e4",
    "mem": "#9141ac",
    "gpu": "#2ec27e",
    "disk": "#e66100",
    "net": "#2190a4",
}

# ───────────────────────────── friendly names ─────────────────────────────

FRIENDLY = {
    "gnome-shell": "GNOME Shell (your desktop)",
    "org.gnome.shell": "GNOME Shell (your desktop)",
    "xwayland": "Xwayland (runs older apps)",
    "audio": "Sound & screen sharing",
    "indexer": "File search indexer",
    "gsd": "GNOME background settings",
    "evolution": "Calendar & contacts sync",
    "portal": "App permission portal",
    "gvfs": "Files & drives helper",
    "gnome-software": "Software (updates)",
    "packagekit": "Software updates",
    "packagekitd": "Software updates",
    "networkmanager": "Network manager",
    "systemd": "System manager",
    "init": "System manager",
    "systemd-journald": "System logs",
    "systemd-oomd": "Out-of-memory guard",
    "systemd-resolved": "Network name lookup",
    "systemd-logind": "Login manager",
    "systemd-udevd": "Device manager",
    "firewalld": "Firewall",
    "dbus-broker": "System messaging",
    "dbus": "System messaging",
    "polkit": "Permissions helper",
    "polkitd": "Permissions helper",
    "gdm": "Login screen",
    "bluetooth": "Bluetooth",
    "bluetoothd": "Bluetooth",
    "cups": "Printing",
    "cupsd": "Printing",
    "ibus": "Keyboard input",
    "ibus-daemon": "Keyboard input",
    "goa-daemon": "Online accounts",
    "ollama": "Ollama (local AI)",
    "docker": "Docker",
    "dockerd": "Docker",
    "containerd": "Containers",
    "podman": "Podman containers",
    "upower": "Battery & power",
    "upowerd": "Battery & power",
    "power-profiles-daemon": "Power profiles",
    "thermald": "Temperature control",
    "udisks2": "Disk manager",
    "udisksd": "Disk manager",
    "switcheroo-control": "Graphics switcher",
    "chronyd": "Clock sync",
    "avahi-daemon": "Local network discovery",
    "wpa_supplicant": "Wi-Fi",
    "auditd": "Security audit log",
    "asusd": "ASUS laptop controls",
    "supergfxd": "GPU switcher",
    "nvidia-persistenced": "NVIDIA driver helper",
    "abrtd": "Crash reporter",
    "rtkit-daemon": "Realtime scheduling helper",
    "accounts-daemon": "User accounts",
    "colord": "Color profiles",
    "gnome-remote-desktop": "Remote desktop",
    "mutter-x11-frames": "Window frames",
    "flatpak-system-helper": "Flatpak helper",
    "fwupd": "Firmware updates",
    "geoclue": "Location service",
    "gnome-keyring-daemon": "Passwords & keys",
    "at-spi-bus-launcher": "Accessibility",
    "at-spi2-registryd": "Accessibility",
    "gjs": "GNOME script",
    "sshd": "Remote login (SSH)",
    "dnf5daemon-server": "Software updates (DNF)",
    "gnome-session-manager": "GNOME session",
    "gnome-session-binary": "GNOME session",
    "tuned": "Power tuning",
    "tuned-ppd": "Power profiles",
    "syncthing": "Syncthing",
    "kwalletd": "Passwords & keys",
}

ALIASES = [
    (re.compile(r"^(org\.gnome\.settingsdaemon|gsd-)"), "gsd"),
    (re.compile(r"^(evolution|org\.gnome\.evolution)"), "evolution"),
    (re.compile(r"^(tracker|localsearch)"), "indexer"),
    (re.compile(r"^xdg-.*portal"), "portal"),
    (re.compile(r"^(pipewire|wireplumber|filter-chain)"), "audio"),
    (re.compile(r"^gvfs"), "gvfs"),
    (re.compile(r"ibus"), "ibus"),
    (re.compile(r"^at-spi"), "at-spi-bus-launcher"),
    (re.compile(r"^org\.gnome\.shell"), "gnome-shell"),
]

GENERIC_EXES = {
    "flatpak", "env", "sh", "bash", "python", "python3", "java", "wine",
    "gio", "xdg-open", "sudo", "pkexec", "electron", "gjs", "snap", "steam",
}


def unescape(s):
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)


def alias(key):
    k = key.lower()
    for rx, a in ALIASES:
        if rx.search(k):
            return a
    return k


def classify(cgroup, comm):
    """Return (key, kind, hint, unit). kind is 'app' or 'bg'; unit is (bus, name) for services."""
    last = unescape(cgroup.rstrip("/").rsplit("/", 1)[-1])
    unit = None
    if last.endswith(".service") and not last.startswith("user@"):
        unit = ("user" if "/user@" in cgroup else "system", last)
    if "/app.slice/" in cgroup or last.startswith("app-"):
        m = re.match(r"app-(?:gnome-|flatpak-|kde-|snap-)?(.+?)(?:-\d+)?\.scope$", last)
        if not m:
            m = re.match(r"app-(?:gnome-|flatpak-|kde-)?(.+?)(?:@[^.]*)?\.service$", last)
        if m:
            return "app:" + m.group(1).lower(), "app", m.group(1), unit
        m = re.match(r"dbus-:[\d.]+-(.+?)(?:@\d+)?\.service$", last)
        if m:
            return "app:" + m.group(1).lower(), "app", m.group(1), unit
    m = re.match(r"(.+?)(?:@[^.]*)?\.service$", last)
    if m and m.group(1) not in ("user", "session", "app", "init"):
        k = alias(m.group(1))
        return "svc:" + k, "bg", k, unit
    k = alias(comm)
    return "proc:" + k, "bg", k, None


# Things that would log you out or break the desktop if ended.
CRITICAL = {
    "gnome-shell", "gnome-session-manager", "gnome-session-binary", "gnome-session", "systemd", "init",
    "systemd-logind", "systemd-journald", "systemd-udevd", "dbus-broker", "dbus", "dbus-daemon",
    "gdm", "xwayland", "kernel",
}


CRITICAL_UNITS = re.compile(r"^(org\.gnome\.shell|gnome-session|org\.gnome\.session|systemd-|dbus|gdm|"
                            r"display-manager|user@|user-runtime-dir|getty|xwayland)", re.I)

# Processes that genuinely belong to GNOME Shell (anything else in its cgroup was just launched by it).
SHELL_PARTS = {"gnome-shell", "xwayland", "mutter-x11-frames", "gjs", "gnome-shell-calendar-server",
               "ibus", "at-spi-bus-launcher", "gnome-session-c", "gnome-session-binary"}


def is_critical(g):
    if g["hint"].lower() in CRITICAL:
        return True
    if any(CRITICAL_UNITS.search(u) for _, u in g.get("units", ())):
        return True
    return any(pid in (1, os.getpid()) for pid, *_ in g["procs"])


def unit_props(bus, unit):
    cmd = ["systemctl"] + (["--user"] if bus == "user" else []) + [
        "show", unit, "-p", "Description,Restart,RequiredBy,WantedBy,BoundBy,UpheldBy,TriggeredBy,ActiveState,SubState"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return {}
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


DEP_PROPS = ("RequiredBy", "BoundBy", "UpheldBy", "WantedBy", "TriggeredBy")


def unit_dependents(bus, units):
    """Every live unit that (directly or through others) keeps pulling `units` back up. Targets excluded."""
    seen = set(units)
    queue = list(units)
    result = []
    while queue:
        p = unit_props(bus, queue.pop(0))
        for prop in DEP_PROPS:
            for dep in p.get(prop, "").split():
                if dep in seen or dep.endswith(".target"):
                    continue
                seen.add(dep)
                dp = unit_props(bus, dep)
                # inactive units can't start anything; activating/auto-restart ones (crash loops) can
                if dp.get("ActiveState") in ("active", "activating", "reloading", "deactivating") or \
                        dp.get("SubState") == "auto-restart":
                    result.append(dep)
                    queue.append(dep)
    return result


def find_crash_loops():
    """Services stuck restarting over and over: [(bus, unit, description, restarts)]."""
    found = []
    for bus in ("user", "system"):
        base = ["systemctl"] + (["--user"] if bus == "user" else [])
        try:
            out = subprocess.run(base + ["list-units", "--type=service", "--all", "--plain", "--no-legend",
                                         "--state=activating,failed,auto-restart"],
                                 capture_output=True, text=True, timeout=4).stdout
            units = [line.split()[0] for line in out.splitlines() if line.strip()]
            if not units:
                continue
            out = subprocess.run(base + ["show", "-p", "Id,Description,NRestarts,SubState"] + units,
                                 capture_output=True, text=True, timeout=4).stdout
        except Exception:
            continue
        for block in out.strip().split("\n\n"):
            p = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            try:
                n = int(p.get("NRestarts", "0"))
            except ValueError:
                n = 0
            if n >= 5 and p.get("SubState") in ("auto-restart", "start", "start-pre", "start-post", "failed"):
                found.append((bus, p.get("Id", ""), p.get("Description", ""), n))
    found.sort(key=lambda x: -x[3])
    return found


def stop_unit(bus, unit, done):
    """Ask systemd to stop a unit (polkit asks for a password if needed). done(err_or_None)."""
    try:
        conn = Gio.bus_get_sync(Gio.BusType.SESSION if bus == "user" else Gio.BusType.SYSTEM, None)
    except GLib.Error as e:
        done(e.message)
        return

    def cb(c, res):
        try:
            c.call_finish(res)
            done(None)
        except GLib.Error as e:
            done(Gio.DBusError.strip_remote_error(e) or e.message)

    conn.call("org.freedesktop.systemd1", "/org/freedesktop/systemd1",
              "org.freedesktop.systemd1.Manager", "StopUnit",
              GLib.Variant("(ss)", (unit, "replace")), GLib.VariantType.new("(o)"),
              Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, 60000, None, cb)


# ───────────────────────────── formatting ─────────────────────────────

def fmt_bytes(n, digits=1):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            if unit in ("B", "KB"):
                return f"{n:.0f} {unit}"
            if unit == "MB" and n >= 100:
                return f"{n:.0f} {unit}"
            return f"{n:.{digits}f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def fmt_rate(n):
    return fmt_bytes(n) + "/s"


# ───────────────────────────── GPU reading ─────────────────────────────

class GpuReader:
    def __init__(self):
        self.gpus = []
        self._last_nv = None
        self._last_nv_t = 0
        base = "/sys/bus/pci/devices"
        try:
            devs = sorted(os.listdir(base))
        except OSError:
            devs = []
        for d in devs:
            p = os.path.join(base, d)
            try:
                cls = open(os.path.join(p, "class")).read().strip()
                vendor = open(os.path.join(p, "vendor")).read().strip()
            except OSError:
                continue
            if not cls.startswith("0x03"):
                continue
            if vendor == "0x10de":
                self.gpus.append({"vendor": "nvidia", "path": p, "dedicated": True})
            elif vendor == "0x1002":
                drm = self._drm_for(p)
                dedicated = os.path.exists(os.path.join(p, "mem_info_vram_total"))
                self.gpus.append({"vendor": "amd", "path": p, "drm": drm, "dedicated": dedicated})
            elif vendor == "0x8086":
                self.gpus.append({"vendor": "intel", "path": p, "dedicated": False})
        self.has_smi = shutil.which("nvidia-smi") is not None

    @staticmethod
    def _drm_for(p):
        try:
            return [x for x in os.listdir(os.path.join(p, "drm")) if x.startswith("card")]
        except OSError:
            return []

    def _runtime(self, p):
        try:
            return open(os.path.join(p, "power", "runtime_status")).read().strip()
        except OSError:
            return "active"

    def _read_nvidia(self, g):
        if self._runtime(g["path"]) == "suspended":
            return {"name": "NVIDIA GPU", "state": "sleeping", "procs": {}}
        if not self.has_smi:
            return None
        # Poll less often when idle so the GPU is free to power down.
        now = time.monotonic()
        idle = self._last_nv and self._last_nv.get("util", 0) == 0
        if self._last_nv and now - self._last_nv_t < (10 if idle else 0):
            return self._last_nv
        try:
            out = subprocess.run(["nvidia-smi", "-q", "-x"], capture_output=True, timeout=4).stdout
            root = ET.fromstring(out)
        except Exception:
            return None
        gpu = root.find("gpu")
        if gpu is None:
            return None

        def num(path):
            t = gpu.findtext(path) or ""
            m = re.search(r"[\d.]+", t)
            return float(m.group()) if m else None

        procs = {}
        for pi in gpu.findall("processes/process_info"):
            try:
                pid = int(pi.findtext("pid"))
                mem = num_text(pi.findtext("used_memory"))
                procs[pid] = procs.get(pid, 0) + (mem or 0) * 1024 * 1024
            except (TypeError, ValueError):
                pass
        res = {
            "name": (gpu.findtext("product_name") or "NVIDIA GPU").replace("NVIDIA ", "").replace(" Laptop GPU", ""),
            "state": "active",
            "used": (num("fb_memory_usage/used") or 0) * 1024 * 1024,
            "total": (num("fb_memory_usage/total") or 0) * 1024 * 1024,
            "util": num("utilization/gpu_util") or 0,
            "temp": num("temperature/gpu_temp"),
            "procs": procs,
        }
        self._last_nv, self._last_nv_t = res, now
        return res

    def _read_amd(self, g):
        p = g["path"]
        try:
            used = int(open(os.path.join(p, "mem_info_vram_used")).read())
            total = int(open(os.path.join(p, "mem_info_vram_total")).read())
        except OSError:
            return None
        try:
            util = float(open(os.path.join(p, "gpu_busy_percent")).read())
        except OSError:
            util = 0
        state = "sleeping" if self._runtime(p) == "suspended" else "active"
        return {"name": "AMD GPU", "state": state, "used": used, "total": total, "util": util, "temp": None, "procs": {}}

    def read(self):
        dedicated = [g for g in self.gpus if g["dedicated"]]
        for g in dedicated:
            r = self._read_nvidia(g) if g["vendor"] == "nvidia" else self._read_amd(g)
            if r:
                r["dedicated"] = True
                return r
        if self.gpus:
            return {"name": "Built-in graphics", "state": "integrated", "dedicated": False, "procs": {}}
        return None


def num_text(t):
    m = re.search(r"[\d.]+", t or "")
    return float(m.group()) if m else None


# ───────────────────────────── data collection ─────────────────────────────

class Collector:
    def __init__(self, apps):
        self.apps = apps
        self.ncpu = psutil.cpu_count() or 1
        self.gpu = GpuReader()
        self.cg_cache = {}
        self.crash_loops = []
        self.tick = 0
        self.prev_t = time.monotonic()
        self.prev_disk = psutil.disk_io_counters()
        self.prev_net = self._net()
        psutil.cpu_percent(None)
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except psutil.Error:
                pass

    @staticmethod
    def _net():
        tot = [0, 0]
        for nic, c in psutil.net_io_counters(pernic=True).items():
            if nic == "lo":
                continue
            tot[0] += c.bytes_recv
            tot[1] += c.bytes_sent
        return tot

    def _group_of(self, pid, ct, comm):
        key = (pid, ct)
        g = self.cg_cache.get(key)
        if g is None:
            try:
                cg = open(f"/proc/{pid}/cgroup").read().strip().split("::", 1)[-1]
            except OSError:
                cg = ""
            g = classify(cg, comm)
            if g[0] == "svc:gnome-shell" and alias(comm) not in SHELL_PARTS:
                # an app GNOME Shell launched without its own scope: attribute it to the app, not the shell
                k = alias(comm)
                g = ("app:" + k, "app", k, None) if self.apps.lookup(k) else ("proc:" + k, "bg", k, None)
            self.cg_cache[key] = g
        return g

    def sample(self):
        now = time.monotonic()
        dt = max(now - self.prev_t, 0.1)
        self.prev_t = now

        cpu = psutil.cpu_percent(None)
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        try:
            du = psutil.disk_usage("/")
        except OSError:
            du = None
        dio = psutil.disk_io_counters()
        rd = wr = 0
        if dio and self.prev_disk:
            rd = (dio.read_bytes - self.prev_disk.read_bytes) / dt
            wr = (dio.write_bytes - self.prev_disk.write_bytes) / dt
        self.prev_disk = dio
        net = self._net()
        down = (net[0] - self.prev_net[0]) / dt
        up = (net[1] - self.prev_net[1]) / dt
        self.prev_net = net

        temp = None
        try:
            t = psutil.sensors_temperatures()
            for name in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "acpitz"):
                if t.get(name):
                    pkg = [x for x in t[name] if "Package" in (x.label or "") or "Tctl" in (x.label or "")]
                    temp = (pkg or t[name])[0].current
                    break
        except Exception:
            pass

        if self.tick % (5 if self.crash_loops else 15) == 0:
            self.crash_loops = find_crash_loops()
        self.tick += 1

        gpu = self.gpu.read()
        gpu_procs = gpu["procs"] if gpu else {}

        groups = {}
        alive = set()
        for p in psutil.process_iter(["name", "memory_info", "username", "create_time"]):
            try:
                mi = p.info["memory_info"]
                if mi is None or mi.rss == 0:
                    continue
                c = p.cpu_percent(None) / self.ncpu
                comm = p.info["name"] or "?"
            except psutil.Error:
                continue
            mem = max(mi.rss - getattr(mi, "shared", 0), 0)
            ct = p.info["create_time"]
            key, kind, hint, unit = self._group_of(p.pid, ct, comm)
            alive.add((p.pid, ct))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "key": key, "kind": kind, "hint": hint, "mem": 0, "cpu": 0.0, "vram": 0,
                    "procs": [], "user": p.info["username"], "units": set(),
                }
            if unit:
                g["units"].add(unit)
            v = gpu_procs.get(p.pid, 0)
            g["mem"] += mem
            g["cpu"] += c
            g["vram"] += v
            g["procs"].append((p.pid, comm, mem, c, v))

        # forget dead pids
        self.cg_cache = {k: v for k, v in self.cg_cache.items() if k in alive}

        for g in groups.values():
            name, icon, is_app = self.apps.resolve(g)
            g["name"], g["icon"], g["is_app"] = name, icon, is_app

        return {
            "cpu": cpu, "ncpu": self.ncpu, "temp": temp,
            "mem_used": vm.total - vm.available, "mem_total": vm.total,
            "swap_used": sw.used, "swap_total": sw.total,
            "disk": du, "read": max(rd, 0), "write": max(wr, 0),
            "down": max(down, 0), "up": max(up, 0),
            "gpu": gpu, "groups": groups, "crash_loops": list(self.crash_loops),
        }


class AppIndex:
    """Maps cgroup / process names to desktop apps (name + icon)."""

    def __init__(self):
        self.idx = {}
        self.loose = {}
        self.cache = {}
        for ai in Gio.AppInfo.get_all():
            if not hasattr(ai, "get_startup_wm_class"):
                continue
            entry = (ai.get_display_name() or ai.get_name(), ai.get_icon())
            did = (ai.get_id() or "").removesuffix(".desktop").lower()
            if did:
                self.idx.setdefault(did, entry)
            wm = ai.get_startup_wm_class()
            if wm:
                self.idx.setdefault(wm.lower(), entry)
            if did and "-" in did and "." not in did:
                self.loose.setdefault(did.split("-")[0], entry)
            exe = ai.get_executable()
            if exe:
                b = os.path.basename(exe).lower()
                if b not in GENERIC_EXES:
                    self.idx.setdefault(b, entry)

    def lookup(self, key):
        k = key.lower()
        if k in self.cache:
            return self.cache[k]
        res = None
        cand = k
        while cand:
            if cand in self.idx:
                res = self.idx[cand]
                break
            if "." not in cand:
                break
            cand = cand.rsplit(".", 1)[0]
            if cand.count(".") < 1:  # don't match bare "org"/"com"
                break
        if res is None and "." in k:
            parts = k.split(".")
            for part in reversed(parts[1:]):
                if part in self.idx and part not in ("desktop", "gnome"):
                    res = self.idx[part]
                    break
        if res is None:
            last = k.rsplit(".", 1)[-1]
            res = self.loose.get(last)
        self.cache[k] = res
        return res

    def resolve(self, g):
        hint = g["hint"]
        if g["kind"] == "app":
            hit = self.lookup(hint)
            if hit:
                return hit[0], hit[1], True
            nice = FRIENDLY.get(hint.lower())
            return nice or prettify(hint), None, True
        nice = FRIENDLY.get(hint.lower())
        if nice:
            return nice, None, False
        hit = self.lookup(hint)
        if hit:
            return hit[0], hit[1], True
        return prettify(hint), None, False


def prettify(s):
    if "." in s and s.count(".") >= 2:
        s = s.rsplit(".", 1)[-1]
    return s[:1].upper() + s[1:] if s else s


# ───────────────────────────── widgets ─────────────────────────────

class Sparkline(Gtk.DrawingArea):
    def __init__(self, color, autoscale=False, floor=1.0):
        super().__init__()
        self.values = []
        self.autoscale = autoscale
        self.floor = floor
        self.rgba = Gdk.RGBA()
        self.rgba.parse(color)
        self.set_content_height(44)
        self.set_hexpand(True)
        self.set_draw_func(self._draw)

    def push(self, v):
        self.values.append(v)
        if len(self.values) > HISTORY:
            self.values.pop(0)
        self.queue_draw()

    def _draw(self, _a, cr, w, h):
        vals = self.values
        if len(vals) < 2:
            return
        top = max(max(vals), self.floor) if self.autoscale else 1.0
        n = HISTORY - 1
        pad = 2
        pts = []
        start = HISTORY - len(vals)
        for i, v in enumerate(vals):
            x = (start + i) / n * w
            y = h - pad - min(max(v / top, 0), 1) * (h - pad * 2)
            pts.append((x, y))
        r, g, b = self.rgba.red, self.rgba.green, self.rgba.blue

        def path():
            cr.move_to(*pts[0])
            for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
                mx = (x0 + x1) / 2
                cr.curve_to(mx, y0, mx, y1, x1, y1)

        import cairo
        path()
        cr.line_to(pts[-1][0], h)
        cr.line_to(pts[0][0], h)
        cr.close_path()
        grad = cairo.LinearGradient(0, 0, 0, h)
        grad.add_color_stop_rgba(0, r, g, b, 0.30)
        grad.add_color_stop_rgba(1, r, g, b, 0.0)
        cr.set_source(grad)
        cr.fill()
        path()
        cr.set_source_rgba(r, g, b, 1)
        cr.set_line_width(2)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)
        cr.set_line_join(cairo.LINE_JOIN_ROUND)
        cr.stroke()


class StatCard(Gtk.Box):
    def __init__(self, title, icon, color_key, autoscale=False, floor=1.0):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class("card")
        self.add_css_class("stat-card")
        self.add_css_class(f"c-{color_key}")

        head = Gtk.Box(spacing=8)
        ic = Gtk.Image.new_from_icon_name(icon)
        ic.add_css_class("stat-icon")
        head.append(ic)
        t = Gtk.Label(label=title.upper(), xalign=0, hexpand=True)
        t.add_css_class("stat-title")
        head.append(t)
        self.pill = Gtk.Label()
        self.pill.add_css_class("pill")
        head.append(self.pill)
        self.append(head)

        self.value = Gtk.Label(xalign=0)
        self.value.add_css_class("stat-value")
        self.value.set_margin_top(8)
        self.append(self.value)
        self.detail = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.detail.add_css_class("stat-detail")
        self.append(self.detail)
        self.detail2 = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.detail2.add_css_class("stat-detail")
        self.detail2.add_css_class("dim-label")
        self.append(self.detail2)

        self.spark = Sparkline(COLORS[color_key], autoscale, floor)
        self.spark.set_margin_top(10)
        self.append(self.spark)

    def set(self, value, detail, detail2, status, level, spark=None):
        self.value.set_label(value)
        self.detail.set_label(detail)
        self.detail2.set_label(detail2)
        self.detail2.set_visible(bool(detail2))
        self.pill.set_label(status)
        for c in ("good", "warn", "bad", "calm"):
            self.pill.remove_css_class(c)
        self.pill.add_css_class(level)
        if spark is not None:
            self.spark.push(spark)


FALLBACK_APP_ICON = Gio.ThemedIcon.new("application-x-executable")
FALLBACK_BG_ICON = Gio.ThemedIcon.new("emblem-system-symbolic")


class GroupRow(Gtk.ListBoxRow):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.rank = 0
        self.group = None
        box = Gtk.Box(spacing=14, margin_top=10, margin_bottom=10, margin_start=14, margin_end=16)
        self.icon = Gtk.Image(pixel_size=32)
        box.append(self.icon)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, hexpand=True)
        self.name = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.name.add_css_class("row-name")
        self.sub = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.sub.add_css_class("caption")
        self.sub.add_css_class("dim-label")
        texts.append(self.name)
        texts.append(self.sub)
        box.append(texts)
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, valign=Gtk.Align.CENTER)
        right.set_size_request(150, -1)
        self.val = Gtk.Label(xalign=1)
        self.val.add_css_class("row-value")
        self.bar = Gtk.ProgressBar()
        self.bar.add_css_class("usage")
        right.append(self.val)
        right.append(self.bar)
        box.append(right)
        self.set_child(box)
        self._icon_ref = None

    def update(self, g, metric, snap, top=1):
        self.group = g
        if self.name.get_label() != g["name"]:
            self.name.set_label(g["name"])
        icon = g["icon"] or (FALLBACK_APP_ICON if g["is_app"] else FALLBACK_BG_ICON)
        if icon is not self._icon_ref:
            self.icon.set_from_gicon(icon)
            self.icon.set_pixel_size(32 if g["icon"] else 22)
            self._icon_ref = icon
        n = len(g["procs"])
        kind = "App" if g["is_app"] else "Background"
        self.sub.set_label(f"{kind} · {n} process{'es' if n != 1 else ''}")
        for c in ("cpu", "mem", "gpu"):
            self.bar.remove_css_class(c)
        self.bar.add_css_class(metric)
        if metric == "mem":
            self.val.set_label(fmt_bytes(g["mem"]))
            self.bar.set_fraction(min(g["mem"] / top, 1))
        elif metric == "cpu":
            self.val.set_label(f"{g['cpu']:.1f}%" if g["cpu"] < 10 else f"{g['cpu']:.0f}%")
            self.bar.set_fraction(min(g["cpu"] / top, 1))
        else:
            self.val.set_label(fmt_bytes(g["vram"]))
            self.bar.set_fraction(min(g["vram"] / top, 1))


def unit_label(u):
    return u.removesuffix(".service")


class DetailDialog(Adw.Dialog):
    def __init__(self, win, row):
        super().__init__()
        self.win = win
        self.key = row.key
        g = row.group
        self.group = g
        self.prows = {}
        self.set_title(g["name"])
        self.set_content_width(540)
        self.set_content_height(600)

        # Service facts (who restarts it, who needs it)
        self.units = sorted(g["units"])
        self.restarts = False
        self.used_by = []      # [(bus, unit)] other services that need this one
        self.autostart = False
        desc = None
        for bus, unit in self.units:
            p = unit_props(bus, unit)
            desc = desc or p.get("Description")
            if p.get("Restart", "no") not in ("no", ""):
                self.restarts = True
            for prop in DEP_PROPS:
                if any(d.endswith(".target") for d in p.get(prop, "").split()):
                    self.autostart = True
        for bus in {b for b, _ in self.units}:
            for dep in unit_dependents(bus, [u for b, u in self.units if b == bus]):
                self.used_by.append((bus, dep))
        self.critical = is_critical(g)

        tv = Adw.ToolbarView()
        tv.add_top_bar(Adw.HeaderBar())
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                       margin_top=6, margin_bottom=24, margin_start=24, margin_end=24)

        top = Gtk.Box(spacing=14)
        img = Gtk.Image(pixel_size=56)
        img.set_from_gicon(g["icon"] or (FALLBACK_APP_ICON if g["is_app"] else FALLBACK_BG_ICON))
        top.append(img)
        tb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER)
        nm = Gtk.Label(label=g["name"], xalign=0, wrap=True)
        nm.add_css_class("title-2")
        tb.append(nm)
        kind = Gtk.Label(xalign=0, wrap=True)
        kind.add_css_class("dim-label")
        if g["is_app"] and not self.units:
            kind.set_label("An app you opened")
        elif self.units:
            mine = all(b == "user" for b, _ in self.units)
            kind.set_label((desc + " · " if desc else "") +
                           ("Your background service" if mine else "System background service"))
        else:
            kind.set_label("Runs in the background")
        tb.append(kind)
        top.append(tb)
        page.append(top)

        stats = Gtk.Box(spacing=10, homogeneous=True)
        self.s_mem = self._stat(stats, "Memory", "mem")
        self.s_cpu = self._stat(stats, "Processor", "cpu")
        self.s_gpu = self._stat(stats, "Graphics memory", "gpu")
        page.append(stats)

        if self.units:
            facts = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            facts.add_css_class("boxed-list")
            facts.append(Adw.ActionRow(title="Service", subtitle=", ".join(u for _, u in self.units),
                                       subtitle_selectable=True))
            if self.restarts:
                facts.append(Adw.ActionRow(title="Restarts by itself",
                                           subtitle="If it's killed it comes back, so Pulse stops it properly instead"))
            if self.used_by:
                facts.append(Adw.ActionRow(title="Kept running by",
                                           subtitle=" → ".join(unit_label(u) for _, u in self.used_by) +
                                           " — these start it again if only it is stopped"))
            if self.autostart:
                facts.append(Adw.ActionRow(title="Starts automatically", subtitle="Comes back next time you log in"))
            page.append(facts)

        lbl = Gtk.Label(label="Processes", xalign=0)
        lbl.add_css_class("heading")
        page.append(lbl)
        self.plist = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.plist.add_css_class("boxed-list")
        page.append(self.plist)

        if self.critical:
            note = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER,
                             label="This keeps your desktop running. Ending it would close your session, "
                                   "so Pulse doesn't allow it.")
            note.add_css_class("dim-label")
            page.append(note)
        else:
            label = "Stop Service" if self.units else ("End This App" if g["is_app"] else "End Process")
            end = Gtk.Button(label=label)
            end.add_css_class("destructive-action")
            end.add_css_class("pill")
            end.set_halign(Gtk.Align.CENTER)
            end.connect("clicked", self._confirm)
            page.append(end)

        sc = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, propagate_natural_height=True)
        sc.set_child(page)
        tv.set_content(sc)
        self.set_child(tv)
        self.refresh(g)

    def _stat(self, parent, title, cls):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        b.add_css_class("card")
        b.add_css_class("mini-stat")
        b.add_css_class(f"c-{cls}")
        t = Gtk.Label(label=title, xalign=0)
        t.add_css_class("caption")
        t.add_css_class("dim-label")
        v = Gtk.Label(xalign=0)
        v.add_css_class("mini-value")
        b.append(t)
        b.append(v)
        parent.append(b)
        return v

    def refresh(self, g):
        """Update in place so the list doesn't flicker or lose its scroll position."""
        self.group = g
        self.s_mem.set_label(fmt_bytes(g["mem"]))
        self.s_cpu.set_label(f"{g['cpu']:.1f}%")
        self.s_gpu.set_label(fmt_bytes(g["vram"]) if g["vram"] else "—")
        seen = set()
        for pid, comm, mem, cpu, vram in sorted(g["procs"], key=lambda x: -x[2]):
            seen.add(pid)
            extra = f"  ·  {fmt_bytes(vram)} VRAM" if vram else ""
            text = f"{fmt_bytes(mem)}  ·  {cpu:.1f}%{extra}"
            if pid in self.prows:
                self.prows[pid][1].set_label(text)
                continue
            r = Adw.ActionRow(title=comm, subtitle=f"ID {pid}")
            r.set_title_lines(1)
            lab = Gtk.Label(label=text)
            lab.add_css_class("dim-label")
            lab.add_css_class("numeric")
            r.add_suffix(lab)
            self.plist.append(r)
            self.prows[pid] = (r, lab)
        for pid in [p for p in self.prows if p not in seen]:
            self.plist.remove(self.prows.pop(pid)[0])

    def _confirm(self, _b):
        g = self.group
        if self.units:
            heading = f"Stop {g['name']}?"
            parts = [f"This stops the {', '.join(unit_label(u) for _, u in self.units)} service."]
            if self.used_by:
                parts.append(f"{', '.join(unit_label(u) for _, u in self.used_by)} will start it "
                             "again — choose “Stop All” to stop those too.")
            if self.autostart:
                parts.append("It will start again next time you log in.")
            if any(b == "system" for b, _ in self.units):
                parts.append("You may be asked for your password.")
            d = Adw.AlertDialog(heading=heading, body=" ".join(parts))
            d.add_response("cancel", "Cancel")
            if self.used_by:
                d.add_response("stop-all", "Stop All")
                d.set_response_appearance("stop-all", Adw.ResponseAppearance.DESTRUCTIVE)
            d.add_response("stop", "Stop")
            d.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
        else:
            mine = g["user"] == os.environ.get("USER")
            body = (f"Unsaved work in {g['name']} may be lost." if g["is_app"] and mine else
                    f"{g['name']} runs in the background. Ending it may cause problems until you restart.")
            d = Adw.AlertDialog(heading=f"End {g['name']}?", body=body)
            d.add_response("cancel", "Cancel")
            d.add_response("term", "End")
            d.set_response_appearance("term", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_default_response("cancel")
        d.set_close_response("cancel")
        d.connect("response", self._on_response)
        d.present(self)

    def _on_response(self, _d, resp):
        if resp == "cancel":
            return
        g = self.group
        if resp in ("stop", "stop-all"):
            targets = list(self.units) + (self.used_by if resp == "stop-all" else [])
            self.win.stop_services(g, targets, self.used_by if resp == "stop" else [], self.restarts)
        else:
            self.win.end_processes(g)
        self.close()


# ───────────────────────────── window ─────────────────────────────

CSS = """
.stat-card { padding: 18px 18px 14px 18px; border-radius: 18px; }
.stat-title { font-size: 11px; font-weight: 700; letter-spacing: 1px; opacity: 0.6; }
.stat-value { font-size: 32px; font-weight: 800; font-feature-settings: "tnum"; }
.stat-detail { font-size: 13px; }
.stat-icon { opacity: 0.75; }
.c-cpu .stat-icon { color: #3584e4; }
.c-mem .stat-icon { color: #9141ac; }
.c-gpu .stat-icon { color: #2ec27e; }
.c-disk .stat-icon { color: #e66100; }
.c-net .stat-icon { color: #2190a4; }
.pill { border-radius: 99px; padding: 2px 10px; font-size: 11px; font-weight: 700; }
.pill.good { background: alpha(@success_color, 0.15); color: @success_color; }
.pill.calm { background: alpha(@accent_color, 0.12); color: @accent_color; }
.pill.warn { background: alpha(@warning_color, 0.18); color: @warning_color; }
.pill.bad  { background: alpha(@error_color, 0.15); color: @error_color; }
.summary-title { font-size: 28px; font-weight: 800; }
.summary-sub { font-size: 15px; }
.dot { min-width: 12px; min-height: 12px; border-radius: 99px; }
.dot.good { background: @success_color; }
.dot.warn { background: @warning_color; }
.dot.bad  { background: @error_color; }
.section-title { font-size: 18px; font-weight: 700; }
.row-name { font-weight: 600; }
.row-value { font-weight: 700; font-feature-settings: "tnum"; }
progressbar.usage trough, progressbar.usage progress { min-height: 6px; border-radius: 99px; }
progressbar.usage trough { background: alpha(currentColor, 0.08); }
progressbar.usage.cpu progress { background: #3584e4; }
progressbar.usage.mem progress { background: #9141ac; }
progressbar.usage.gpu progress { background: #2ec27e; }
.mini-stat { padding: 12px 14px; border-radius: 14px; }
.mini-value { font-size: 20px; font-weight: 800; font-feature-settings: "tnum"; }
.empty-note { padding: 28px; }
"""


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Pulse")
        self.set_default_size(1040, 820)
        self.metric = "mem"
        self.show_all = False
        self.snap = None
        self.rows = {}
        self.dialog = None
        self.query = ""
        self.watch = {}

        self.toasts = Adw.ToastOverlay()
        tv = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        hb.set_title_widget(Adw.WindowTitle(title="Pulse", subtitle=""))
        self.wtitle = hb.get_title_widget()
        search_btn = Gtk.ToggleButton(icon_name="system-search-symbolic", tooltip_text="Find an app")
        hb.pack_start(search_btn)
        menu = Gio.Menu()
        menu.append("About Pulse", "app.about")
        mb = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        hb.pack_end(mb)
        tv.add_top_bar(hb)

        self.searchbar = Gtk.SearchBar()
        entry = Gtk.SearchEntry(placeholder_text="Find an app or process…")
        entry.set_size_request(360, -1)
        self.searchbar.set_child(entry)
        self.searchbar.connect_entry(entry)
        self.searchbar.set_key_capture_widget(self)
        search_btn.bind_property("active", self.searchbar, "search-mode-enabled",
                                 GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE)
        entry.connect("search-changed", self._on_search)
        tv.add_top_bar(self.searchbar)

        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=28,
                       margin_top=20, margin_bottom=36, margin_start=24, margin_end=24)

        # summary
        sb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        line = Gtk.Box(spacing=12)
        self.dot = Gtk.Box(valign=Gtk.Align.CENTER)
        self.dot.add_css_class("dot")
        line.append(self.dot)
        self.sum_title = Gtk.Label(label="Taking a look…", xalign=0, wrap=True)
        self.sum_title.add_css_class("summary-title")
        line.append(self.sum_title)
        sb.append(line)
        self.sum_sub = Gtk.Label(xalign=0, wrap=True)
        self.sum_sub.add_css_class("summary-sub")
        self.sum_sub.add_css_class("dim-label")
        sb.append(self.sum_sub)
        self.sum_btn = Gtk.Button(halign=Gtk.Align.START, visible=False, margin_top=6)
        self.sum_btn.add_css_class("pill")
        self.sum_btn.connect("clicked", self._on_summary_action)
        self.sum_action = None
        sb.append(self.sum_btn)
        page.append(sb)

        # cards
        self.c_cpu = StatCard("Processor", "pulse-cpu-symbolic", "cpu")
        self.c_mem = StatCard("Memory", "pulse-memory-symbolic", "mem")
        self.c_gpu = StatCard("Graphics", "pulse-gpu-symbolic", "gpu")
        self.c_disk = StatCard("Storage", "drive-harddisk-symbolic", "disk", autoscale=True, floor=2e6)
        self.c_net = StatCard("Internet", "network-wireless-symbolic", "net", autoscale=True, floor=200e3)
        cards = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        for group, per_line in (((self.c_cpu, "cpu"), (self.c_mem, "mem"), (self.c_gpu, "gpu")), 3), \
                               (((self.c_disk, None), (self.c_net, None)), 2):
            flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True,
                               column_spacing=14, row_spacing=14, min_children_per_line=1,
                               max_children_per_line=per_line)
            for card, metric in group:
                card.set_size_request(220, -1)
                flow.append(card)
                if metric:
                    gc = Gtk.GestureClick()
                    gc.connect("released", lambda *_a, m=metric: self.toggles.set_active_name(m))
                    card.add_controller(gc)
                    card.set_cursor(Gdk.Cursor.new_from_name("pointer"))
                    card.set_tooltip_text("Show what's using this")
            for ch in list(flow):
                ch.set_focusable(False)
            cards.append(flow)
        page.append(cards)

        # list header
        lh = Gtk.Box(spacing=12)
        self.list_title = Gtk.Label(xalign=0, hexpand=True, wrap=True)
        self.list_title.add_css_class("section-title")
        lh.append(self.list_title)
        self.toggles = Adw.ToggleGroup()
        self.toggles.add_css_class("round")
        for name, label in (("mem", "Memory"), ("cpu", "Processor"), ("gpu", "Graphics")):
            self.toggles.add(Adw.Toggle(name=name, label=label))
        self.toggles.set_active_name("mem")
        self.toggles.connect("notify::active-name", self._on_metric)
        lh.append(self.toggles)
        page.append(lh)

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_sort_func(self._sort)
        self.listbox.set_filter_func(self._filter)
        self.listbox.connect("row-activated", self._open_detail)
        self.empty = Gtk.Label(label="Nothing here right now", wrap=True)
        self.empty.add_css_class("dim-label")
        self.empty.add_css_class("empty-note")
        self.listbox.set_placeholder(self.empty)
        page.append(self.listbox)

        self.more = Gtk.Button(halign=Gtk.Align.CENTER)
        self.more.add_css_class("pill")
        self.more.add_css_class("flat")
        self.more.connect("clicked", self._toggle_more)
        page.append(self.more)

        clamp = Adw.Clamp(maximum_size=1120, tightening_threshold=900)
        clamp.set_child(page)
        sc = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        sc.set_child(clamp)
        sc.get_child().set_scroll_to_focus(False)
        tv.set_content(sc)
        self.toasts.set_child(tv)
        self.set_content(self.toasts)
        self._update_list_title()

    def toast(self, msg, button=None, on_click=None, timeout=4):
        t = Adw.Toast(title=msg, timeout=timeout)
        if button:
            t.set_button_label(button)
            t.connect("button-clicked", lambda *_: on_click())
        self.toasts.add_toast(t)

    def _on_summary_action(self, _b):
        if not self.sum_action:
            return
        label, units = self.sum_action
        names = ", ".join(unit_label(u) for _, u in units)
        d = Adw.AlertDialog(heading=f"{label}?",
                            body=f"This stops {names} until you log in again or start it yourself. "
                                 "Whatever it was trying to do won't run — but it isn't working right now anyway.")
        d.add_response("cancel", "Cancel")
        d.add_response("stop", "Stop")
        d.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_default_response("cancel")
        d.set_close_response("cancel")

        def on_resp(_d, r):
            if r != "stop":
                return
            g = {"key": "loop:" + names, "name": names, "procs": []}
            self.stop_services(g, units, [], False)
        d.connect("response", on_resp)
        d.present(self)

    # ending things
    def stop_services(self, g, targets, used_by, restarts):
        pending = {"n": len(targets), "errors": []}

        def done(err):
            if err:
                pending["errors"].append(err)
            pending["n"] -= 1
            if pending["n"] == 0:
                if pending["errors"]:
                    self.toast(f"Couldn't stop {g['name']}: {pending['errors'][0]}", timeout=6)
                else:
                    extra = len(targets) - len(g.get("units", ())) if g.get("units") else 0
                    self.toast(f"Stopped {g['name']}" + (f" and {extra} related service{'s' if extra > 1 else ''}"
                                                         if extra > 0 else ""))
                    self._watch(g, used_by, restarts)

        for bus, unit in targets:
            stop_unit(bus, unit, done)

    def end_processes(self, g, sig=signal.SIGTERM):
        denied = 0
        pids = [pid for pid, *_ in g["procs"] if pid != os.getpid()]
        for pid in pids:
            try:
                os.kill(pid, sig)
            except PermissionError:
                denied += 1
            except ProcessLookupError:
                pass
        if denied == len(pids) and pids:
            self.toast(f"Couldn't end {g['name']} — it belongs to the system and needs admin rights", timeout=6)
            return
        self.toast(f"Ending {g['name']}…", timeout=2)
        GLib.timeout_add(3000, self._check_ended, g, pids, sig)
        self._watch(g, [], False)

    def _check_ended(self, g, pids, sig):
        left = []
        for p in pids:
            try:
                if psutil.Process(p).status() != psutil.STATUS_ZOMBIE:
                    left.append(p)
            except psutil.Error:
                pass
        if not left:
            return False
        if sig == signal.SIGTERM:
            self.toast(f"{g['name']} isn't responding", button="Force End", timeout=8,
                       on_click=lambda: self.end_processes(dict(g, procs=[(p,) for p in left]), signal.SIGKILL))
        else:
            self.toast(f"Couldn't end {g['name']}", timeout=5)
        return False

    def _watch(self, g, used_by, restarts):
        """Notice if something brings the app/service right back."""
        self.watch[g["key"]] = {
            "until": time.monotonic() + 20, "old": {p[0] for p in g["procs"]},
            "name": g["name"], "used_by": used_by, "restarts": restarts,
        }

    def _check_watch(self, groups):
        now = time.monotonic()
        for key, w in list(self.watch.items()):
            if now > w["until"]:
                del self.watch[key]
                continue
            g = groups.get(key)
            if g and {p[0] for p in g["procs"]} - w["old"]:
                del self.watch[key]
                if w["used_by"]:
                    who = ", ".join(unit_label(u) for _, u in w["used_by"])
                    self.toast(f"{w['name']} was started again by {who}", button="Stop All", timeout=10,
                               on_click=lambda g=g, ub=w["used_by"]: self.stop_services(
                                   g, sorted(g["units"]) + ub, [], False))
                else:
                    self.toast(f"{w['name']} started again on its own", timeout=6)

    # list behaviour
    def _value(self, g):
        return g["mem"] if self.metric == "mem" else g["cpu"] if self.metric == "cpu" else g["vram"]

    def _sort(self, a, b):
        return a.rank - b.rank

    def _filter(self, row):
        g = row.group
        if g is None:
            return False
        if self.query:
            q = self.query
            return q in g["name"].lower() or q in g["hint"].lower() or any(q in p[1].lower() for p in g["procs"])
        if self.metric == "gpu" and g["vram"] <= 0:
            return False
        return self.show_all or row.rank < ROW_LIMIT

    def _on_search(self, entry):
        self.query = entry.get_text().strip().lower()
        self.listbox.invalidate_filter()
        self._update_more()

    def _on_metric(self, *_a):
        self.metric = self.toggles.get_active_name() or "mem"
        self._update_list_title()
        if self.snap:
            self._apply_rows(self.snap)

    def _toggle_more(self, _b):
        self.show_all = not self.show_all
        self.listbox.invalidate_filter()
        self._update_more()

    def _update_list_title(self):
        self.list_title.set_label({
            "mem": "What's using your memory",
            "cpu": "What's keeping your processor busy",
            "gpu": "What's using your graphics card",
        }[self.metric])
        self.empty.set_label({
            "gpu": "No apps are using the graphics card right now.\nIt's resting to save battery.",
        }.get(self.metric, "Nothing here right now"))

    def _update_more(self):
        if not self.snap or self.query:
            self.more.set_visible(False)
            return
        groups = self.snap["groups"].values()
        n = sum(1 for g in groups if self.metric != "gpu" or g["vram"] > 0)
        self.more.set_visible(n > ROW_LIMIT)
        self.more.set_label("Show fewer" if self.show_all else f"Show all {n}")

    def _open_detail(self, _lb, row):
        if row.group is None:
            return
        self.dialog = DetailDialog(self, row)
        self.dialog.connect("closed", lambda *_: setattr(self, "dialog", None))
        self.dialog.present(self)

    # updates
    def apply(self, snap):
        self.snap = snap
        self._apply_cards(snap)
        self._apply_rows(snap)
        self._apply_summary(snap)
        self._check_watch(snap["groups"])
        if self.dialog and self.dialog.key in snap["groups"]:
            self.dialog.refresh(snap["groups"][self.dialog.key])
        return False

    def _apply_rows(self, snap):
        groups = snap["groups"]
        order = sorted(groups.values(), key=lambda g: (-self._value(g), -g["mem"], g["name"]))
        top = max((self._value(order[0]) if order else 0), 1e-9)
        if self.metric == "cpu":
            top = max(top, 5.0)  # don't fill the bar for tiny CPU blips
        for i, g in enumerate(order):
            row = self.rows.get(g["key"])
            if row is None:
                row = self.rows[g["key"]] = GroupRow(g["key"])
                self.listbox.append(row)
            row.rank = i
            row.update(g, self.metric, snap, top)
        for k in [k for k in self.rows if k not in groups]:
            self.listbox.remove(self.rows.pop(k))
        self.listbox.invalidate_sort()
        self.listbox.invalidate_filter()
        self._update_more()

    def _apply_cards(self, s):
        cpu = s["cpu"]
        lvl = ("Relaxed", "good") if cpu < 25 else ("Busy", "calm") if cpu < 60 else \
              ("Working hard", "warn") if cpu < 85 else ("Maxed out", "bad")
        temp = f" · {s['temp']:.0f}°C" if s["temp"] else ""
        top = max(s["groups"].values(), key=lambda g: g["cpu"], default=None)
        self.c_cpu.set(f"{cpu:.0f}%", f"{s['ncpu']} cores{temp}",
                       f"Busiest: {top['name']}" if top and top["cpu"] >= 1 else "Nothing heavy running",
                       *lvl, spark=cpu / 100)

        mp = s["mem_used"] / s["mem_total"] * 100
        lvl = ("Plenty free", "good") if mp < 70 else ("Getting full", "warn") if mp < 88 else ("Almost full", "bad")
        swap = ""
        if s["swap_used"] > 256e6:
            swap = f"+ {fmt_bytes(s['swap_used'])} moved to disk (swap)"
        self.c_mem.set(f"{mp:.0f}%", f"{fmt_bytes(s['mem_used'])} of {fmt_bytes(s['mem_total'], 0)}",
                       swap or f"{fmt_bytes(s['mem_total'] - s['mem_used'])} free", *lvl, spark=mp / 100)

        g = s["gpu"]
        if not g:
            self.c_gpu.set("—", "No graphics card found", "", "Unknown", "calm", spark=0)
        elif g["state"] == "sleeping":
            self.c_gpu.set("Asleep", g.get("name", "GPU"), "Saving battery — wakes up when needed",
                           "Resting", "good", spark=0)
        elif g["state"] == "integrated":
            self.c_gpu.set("Built-in", g["name"], "Shares your system memory", "OK", "good", spark=0)
        else:
            vp = g["used"] / g["total"] * 100 if g["total"] else 0
            lvl = ("Plenty free", "good") if vp < 75 else ("Getting full", "warn") if vp < 92 else ("Almost full", "bad")
            if g["util"] >= 60:
                lvl = ("Working hard", "warn") if lvl[1] == "good" else lvl
            t = f" · {g['temp']:.0f}°C" if g.get("temp") else ""
            self.c_gpu.set(f"{fmt_bytes(g['used'])}", f"of {fmt_bytes(g['total'], 0)} video memory",
                           f"{g['name']} · {g['util']:.0f}% busy{t}", *lvl, spark=g["util"] / 100)

        d = s["disk"]
        io = s["read"] + s["write"]
        if d:
            lvl = ("Lots of space", "good") if d.percent < 80 else ("Filling up", "warn") if d.percent < 92 else ("Almost full", "bad")
            act = "Idle" if io < 50e3 else f"Reading {fmt_rate(s['read'])} · Writing {fmt_rate(s['write'])}"
            self.c_disk.set(f"{fmt_bytes(d.free, 0)}", f"free of {fmt_bytes(d.total, 0)}", act, *lvl, spark=io)

        net = s["down"] + s["up"]
        lvl = ("Quiet", "good") if net < 50e3 else ("Active", "calm") if net < 5e6 else ("Busy", "calm")
        self.c_net.set(f"↓ {fmt_rate(s['down'])}", f"↑ {fmt_rate(s['up'])} upload", "", *lvl, spark=net)

        up = int(time.time() - psutil.boot_time())
        h, m = up // 3600, (up % 3600) // 60
        self.wtitle.set_subtitle(f"On for {h}h {m}m" if h else f"On for {m} min")

    def _apply_summary(self, s):
        groups = list(s["groups"].values())
        top_mem = max(groups, key=lambda g: g["mem"], default=None)
        top_cpu = max(groups, key=lambda g: g["cpu"], default=None)
        mp = s["mem_used"] / s["mem_total"] * 100
        cpu = s["cpu"]
        d = s["disk"]
        g = s["gpu"]

        issues = []  # (severity, title, sub)
        if mp >= 88:
            issues.append((2, "Memory is almost full",
                           f"{top_mem['name']} is using the most ({fmt_bytes(top_mem['mem'])}). "
                           "Closing apps you're not using will speed things up."))
        elif mp >= 75:
            issues.append((1, "Memory is getting full",
                           f"{top_mem['name']} is using the most ({fmt_bytes(top_mem['mem'])})."))
        if cpu >= 85:
            issues.append((2, "Your processor is maxed out",
                           f"{top_cpu['name']} is the busiest ({top_cpu['cpu']:.0f}%). Things may feel slow."))
        elif cpu >= 60:
            issues.append((1, "Your processor is busy", f"{top_cpu['name']} is doing the most work."))
        if d and d.percent >= 92:
            issues.append((2, "Your storage is almost full", f"Only {fmt_bytes(d.free)} left. Try clearing old files."))
        if g and g.get("state") == "active" and g.get("total") and g["used"] / g["total"] > 0.92:
            issues.append((1, "Graphics memory is almost full",
                           "Games or AI apps may slow down or fail to load."))
        loops = s.get("crash_loops") or []
        if loops:
            bus, unit, desc, n = loops[0]
            others = f" ({len(loops) - 1} more service{'s' if len(loops) > 2 else ''} too)" if len(loops) > 1 else ""
            issues.append((1, f"{unit_label(unit)} keeps crashing",
                           f"{desc or unit} has failed and restarted {n:,} times{others}. "
                           "Each restart drags the services it needs back up and wastes battery.",
                           (f"Stop {unit_label(unit)}" if len(loops) == 1 else "Stop Crashing Services",
                            [(b, u) for b, u, _, _ in loops])))
        if s["temp"] and s["temp"] >= 90:
            issues.append((1, "Your processor is running hot", f"It's at {s['temp']:.0f}°C. Make sure the vents aren't blocked."))

        for c in ("good", "warn", "bad"):
            self.dot.remove_css_class(c)
        if issues:
            issues.sort(key=lambda x: -x[0])
            sev, title, sub, *action = issues[0]
            self.dot.add_css_class("bad" if sev == 2 else "warn")
            self.sum_title.set_label(title)
            self.sum_sub.set_label(sub)
            self.sum_action = action[0] if action else None
            self.sum_btn.set_visible(bool(action))
            if action:
                self.sum_btn.set_label(action[0][0])
        else:
            self.dot.add_css_class("good")
            self.sum_action = None
            self.sum_btn.set_visible(False)
            self.sum_title.set_label("Everything's running smoothly")
            if top_mem:
                self.sum_sub.set_label(f"{top_mem['name']} is using the most memory ({fmt_bytes(top_mem['mem'])}). "
                                       "Nothing needs your attention.")


class PulseApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.win = None
        self.collector = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        here = os.path.dirname(os.path.realpath(__file__))
        Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(os.path.join(here, "icons"))
        css = Gtk.CssProvider()
        css.load_from_string(CSS)
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css,
                                                  Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        about = Gio.SimpleAction.new("about", None)
        about.connect("activate", self._about)
        self.add_action(about)
        quit_ = Gio.SimpleAction.new("quit", None)
        quit_.connect("activate", lambda *_: self.quit())
        self.add_action(quit_)
        self.set_accels_for_action("app.quit", ["<Control>q"])
        self.set_accels_for_action("window.close", ["<Control>w"])

    def do_activate(self):
        if self.win:
            self.win.present()
            return
        self.win = Window(self)
        self.win.present()
        self.collector = Collector(AppIndex())
        threading.Thread(target=self._loop, daemon=True).start()
        shot = os.environ.get("PULSE_SCREENSHOT")
        if shot:
            GLib.timeout_add_seconds(int(os.environ.get("PULSE_SHOT_DELAY", "7")), self._shot, shot)

    def _shot(self, path):
        paint = Gtk.WidgetPaintable(widget=self.win)
        w, h = self.win.get_width(), self.win.get_height()
        snap = Gtk.Snapshot()
        paint.snapshot(snap, w, h)
        node = snap.to_node()
        tex = self.win.get_renderer().render_texture(node, None)
        tex.save_to_png(path)
        self.quit()
        return False

    def _loop(self):
        time.sleep(0.6)  # let cpu counters settle for the first sample
        while True:
            try:
                snap = self.collector.sample()
                GLib.idle_add(self.win.apply, snap)
            except Exception as e:  # keep running no matter what
                print("sample failed:", e)
            time.sleep(INTERVAL)

    def _about(self, *_a):
        Adw.AboutDialog(application_name="Pulse", application_icon=APP_ID, version="1.0",
                        comments="A calm, easy-to-read system monitor.",
                        developer_name="samsyk").present(self.win)


if __name__ == "__main__":
    PulseApp().run()
