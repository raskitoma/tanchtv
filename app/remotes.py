"""Remote-control drivers for TanchTV ports.

Each port has a capture card (video) and a device (the thing plugged into it) that we control over the
network. The driver depends on the device type:

  androidtv  Android TV / Google TV / NVIDIA Shield — Android TV Remote protocol v2 (androidtvremote2),
             paired with a 6-character code shown on the TV; optional ADB fallback.
  firetv     Amazon Fire TV — ADB over the network (Fire TV doesn't speak Google's remote protocol);
             "pairing" = accepting the "Allow debugging?" prompt on the TV.
  appletv    Apple TV — pyatv (AirPlay + Companion protocols), paired with a PIN shown on the TV.

All drivers share the same small interface (key / text / launch / pair_start / pair_finish / status), so
the web UI and API don't care which kind of device is on a port.
"""

import asyncio
import json
import logging
import shlex
from pathlib import Path
from urllib.parse import quote

log = logging.getLogger("tanchtv.remotes")

KINDS = {
    "androidtv": "Android TV / Google TV",
    "firetv": "Fire TV",
    "appletv": "Apple TV",
}

# Buttons the UI may send (names without KEYCODE_).
KEYS = {
    "DPAD_UP", "DPAD_DOWN", "DPAD_LEFT", "DPAD_RIGHT", "DPAD_CENTER", "BACK", "HOME", "MENU",
    "MEDIA_PLAY_PAUSE", "MEDIA_NEXT", "MEDIA_PREVIOUS", "MEDIA_FAST_FORWARD", "MEDIA_REWIND",
    "MEDIA_STOP", "VOLUME_UP", "VOLUME_DOWN", "VOLUME_MUTE", "POWER", "SLEEP", "WAKEUP",
    "SETTINGS", "SEARCH", "DEL", "ENTER", "CHANNEL_UP", "CHANNEL_DOWN", "GUIDE", "INFO",
    "CAPTIONS", "PROG_RED", "PROG_GREEN", "PROG_YELLOW", "PROG_BLUE",
}

# App shortcuts: per device type a launch target (Android TV: (deep link, package); Fire TV: package;
# Apple TV: bundle id).
APPS = {
    "youtube": {"name": "YouTube", "androidtv": ("vnd.youtube://", "com.google.android.youtube.tv"),
                "firetv": "com.amazon.firetv.youtube", "appletv": "com.google.ios.youtube"},
    "netflix": {"name": "Netflix", "androidtv": ("https://www.netflix.com/title", "com.netflix.ninja"),
                "firetv": "com.netflix.ninja", "appletv": "com.netflix.Netflix"},
    "plex": {"name": "Plex", "androidtv": ("plex://", "com.plexapp.android"),
             "firetv": "com.plexapp.android", "appletv": "com.plexapp.plex"},
    "disney": {"name": "Disney+", "androidtv": ("https://www.disneyplus.com", "com.disney.disneyplus"),
               "firetv": "com.disney.disneyplus", "appletv": "com.disney.disneyplus"},
    "prime": {"name": "Prime Video", "androidtv": ("https://app.primevideo.com", "com.amazon.amazonvideo.livingroom"),
              "firetv": "com.amazon.firebat", "appletv": "com.amazon.aiv.AIVApp"},
    "twitch": {"name": "Twitch", "androidtv": ("twitch://open", "tv.twitch.android.app"),
               "firetv": "tv.twitch.android.viewer", "appletv": "tv.twitch"},
}


YOUTUBE_ATV = "com.google.android.youtube.tv"


class RemoteError(Exception):
    """Something the user should see (not reachable, not supported, wrong code…)."""


# ======================================================================================
class BaseRemote:
    kind = ""
    unsupported: set[str] = set()      # keys this device type can't do
    pairing_help = ""

    def __init__(self, port: dict, data_dir: Path, store):
        self.port = port
        self.host = (port.get("host") or "").strip()
        self.dir = data_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store = store                 # callable(dict) -> persist creds/flags for this port
        self.state = "starting" if self.host else "no_host"
        self.error = ""
        self._task = None
        self._wake = asyncio.Event()
        self._stopped = False

    # lifecycle
    async def start(self):
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self._stopped = True
        if self._task:
            self._task.cancel()
        await self._close()

    async def _close(self):
        pass

    async def _loop(self):
        while not self._stopped:
            if self.host and self.state in ("starting", "unreachable", "disconnected"):
                try:
                    await self._connect()
                except RemoteError as e:
                    self.error = str(e)
                except Exception as e:  # noqa: BLE001
                    self.state, self.error = "unreachable", f"{type(e).__name__}: {e}"
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    def poke(self):
        self._wake.set()

    async def _connect(self):
        raise NotImplementedError

    # actions
    async def key(self, key: str, direction: str = "SHORT") -> str:
        raise NotImplementedError

    async def text(self, text: str) -> str:
        raise RemoteError("Typing isn't supported on this device.")

    async def launch(self, app_id: str) -> str:
        raise NotImplementedError

    async def pair_start(self) -> dict:
        raise NotImplementedError

    async def pair_finish(self, code: str) -> dict:
        raise RemoteError("This device doesn't use a pairing code.")

    def info(self) -> dict:
        return {}

    def status(self, admin: bool) -> dict:
        s = {"kind": self.kind, "remote": self.state, "unsupported": sorted(self.unsupported)}
        s.update(self.info())
        if admin:
            s.update(host=self.host, remote_error=self.error, pairing_help=self.pairing_help)
        return s

    def require_connected(self):
        if self.state != "connected":
            msg = {"needs_pairing": "This device isn't paired yet (Settings → Ports).",
                   "pairing": "Pairing is in progress.", "no_host": "No device address set (Settings → Ports)."}
            raise RemoteError(msg.get(self.state, "The device isn't reachable right now."))


# ======================================================================================
class AdbMixin:
    """ADB over TCP (adb-shell). Key stored per port in <data>/adbkey."""

    adb = None
    adb_state = "off"       # off | awaiting_approval | connected | error
    adb_error = ""

    async def adb_connect(self, auth_timeout=60):
        from adb_shell.adb_device_async import AdbDeviceTcpAsync
        from adb_shell.auth.keygen import keygen
        from adb_shell.auth.sign_pythonrsa import PythonRSASigner

        if not hasattr(self, "_adb_lock"):
            self._adb_lock = asyncio.Lock()
        async with self._adb_lock:
            if self.adb_state == "connected" and self.adb is not None:
                return
            key = self.dir / "adbkey"
            if not key.exists():
                keygen(str(key))
            signer = PythonRSASigner(Path(str(key) + ".pub").read_text(), key.read_text())
            dev = AdbDeviceTcpAsync(self.host, 5555, default_transport_timeout_s=9.0)
            self.adb_state, self.adb_error = "awaiting_approval", ""
            try:
                await dev.connect(rsa_keys=[signer], auth_timeout_s=auth_timeout)
                self.adb, self.adb_state = dev, "connected"
                (self.dir / "adb_ok").touch()
            except Exception as e:  # noqa: BLE001
                self.adb, self.adb_state = None, "error"
                s = str(e).lower()
                self.adb_error = ("ADB is off on the device (port 5555 refused): turn on ADB / Network debugging in Developer options."
                                  if "refused" in s or "111" in s else
                                  "The device didn't accept the connection. Choose “Allow” on the TV (tick “Always allow”)."
                                  if "auth" in s or "timeout" in s else f"{type(e).__name__}: {e}")
                raise RemoteError(self.adb_error) from e

    async def adb_close(self):
        if self.adb is not None:
            try:
                await self.adb.close()
            except Exception:  # noqa: BLE001
                pass
        self.adb, self.adb_state = None, "off"

    async def adb_shell(self, cmd: str) -> str:
        if self.adb is None:
            await self.adb_connect(auth_timeout=10)
        try:
            return await self.adb.shell(cmd, timeout_s=10)
        except Exception as e:
            self.adb, self.adb_state = None, "error"
            raise RemoteError(f"ADB command failed: {e}") from e

    async def adb_key(self, key: str, direction: str):
        if direction == "END_LONG":
            return
        await self.adb_shell(f"input keyevent {'--longpress ' if direction == 'START_LONG' else ''}KEYCODE_{key}")

    async def adb_text(self, text: str):
        await self.adb_shell("input text " + shlex.quote(text.replace(" ", "%s")))

    async def adb_launch(self, package: str):
        await self.adb_shell(f"monkey -p {shlex.quote(package)} 1")


# ======================================================================================
class AndroidTVRemote(AdbMixin, BaseRemote):
    kind = "androidtv"
    pairing_help = ("Press “Start pairing”: a 6-character code appears on the TV (you'll see it in the picture). "
                    "Type it here.")

    def __init__(self, port, data_dir, store):
        super().__init__(port, data_dir, store)
        self.atv = None
        self.adb_enabled = bool(port.get("adb_enabled"))

    def _make(self):
        from androidtvremote2 import AndroidTVRemote as _ATV
        self.atv = _ATV("TanchTV", str(self.dir / "atv_cert.pem"), str(self.dir / "atv_key.pem"), self.host)
        self.atv.add_is_available_updated_callback(self._on_available)

    def _on_available(self, ok):
        if self.state in ("connected", "unreachable"):
            self.state = "connected" if ok else "unreachable"

    def _invalid_auth(self):
        self.state, self.error = "needs_pairing", "The device rejected the stored pairing; pair again."

    async def start(self):
        if self.host:
            self._make()
            await self.atv.async_generate_cert_if_missing()
        if self.adb_enabled and (self.dir / "adb_ok").exists():
            asyncio.create_task(self._quiet_adb())
        await super().start()

    async def _quiet_adb(self):
        try:
            await self.adb_connect(auth_timeout=10)
        except RemoteError:
            pass

    async def _close(self):
        if self.atv:
            self.atv.disconnect()
        await self.adb_close()

    async def _connect(self):
        from androidtvremote2 import CannotConnect, ConnectionClosed, InvalidAuth
        try:
            await self.atv.async_connect()
            self.state, self.error = "connected", ""
            self.atv.keep_reconnecting(self._invalid_auth)
        except InvalidAuth:
            self.state, self.error = "needs_pairing", ""
        except (CannotConnect, ConnectionClosed, OSError) as e:
            self.state, self.error = "unreachable", str(e)

    async def pair_start(self):
        if not self.atv:
            raise RemoteError("Set the device address first.")
        self.atv.disconnect()
        await self.atv.async_start_pairing()
        self.state, self.error = "pairing", ""
        return {"prompt": "Type the 6-character code shown on the TV.", "code": True}

    async def pair_finish(self, code):
        from androidtvremote2 import ConnectionClosed, InvalidAuth
        try:
            await self.atv.async_finish_pairing(code.strip())
        except InvalidAuth as e:
            self.state, self.error = "needs_pairing", "Wrong code. Start pairing again."
            raise RemoteError(self.error) from e
        except ConnectionClosed as e:
            self.state, self.error = "needs_pairing", "Pairing was cancelled on the TV. Start again."
            raise RemoteError(self.error) from e
        self.state = "starting"
        self.poke()
        return {"done": True}

    async def key(self, key, direction="SHORT"):
        if self.state == "connected":
            self.atv.send_key_command(key, direction)
            return "remote"
        if self.adb_enabled:
            await self.adb_key(key, direction)
            return "adb"
        self.require_connected()

    async def text(self, text):
        if self.state == "connected":
            # YouTube draws its own keyboard, which ignores both input-method text and letter key presses,
            # so search it with its own deep link instead (opens the results for the text).
            if self.atv.current_app == YOUTUBE_ATV:
                self.atv.send_launch_app_command("vnd.youtube://results?search_query=" + quote(text))
                return "youtube"
            try:
                self.atv.send_text(text)
                return "remote"
            except Exception:  # noqa: BLE001
                pass
        if self.adb_enabled:
            await self.adb_text(text)
            return "adb"
        self.require_connected()
        raise RemoteError("Typing needs a text field selected on the TV.")

    async def launch(self, app_id):
        link, pkg = APPS[app_id]["androidtv"]
        if self.state == "connected":
            self.atv.send_launch_app_command(link)
            return "remote"
        if self.adb_enabled:
            await self.adb_launch(pkg)
            return "adb"
        self.require_connected()

    def info(self):
        d = {"adb_enabled": self.adb_enabled, "adb": self.adb_state if self.adb_enabled else "off",
             "adb_error": self.adb_error if self.adb_enabled else ""}
        if self.state == "connected" and self.atv:
            d["is_on"] = self.atv.is_on
            d["current_app"] = self.atv.current_app
            di = self.atv.device_info
            if isinstance(di, dict):
                d["device"] = {k: di.get(k) for k in ("manufacturer", "model", "sw_version")}
        return d

    def status(self, admin):
        s = super().status(admin)
        if not admin:
            for k in ("adb_enabled", "adb", "adb_error"):
                s.pop(k, None)
        return s


# ======================================================================================
class FireTVRemote(AdbMixin, BaseRemote):
    kind = "firetv"
    pairing_help = ("On the Fire TV: Settings → My Fire TV → Developer options → turn on “ADB debugging”. "
                    "(No Developer options? Settings → My Fire TV → About → select the device name 7 times.) "
                    "Then press “Connect” here and choose “Allow” on the TV — tick “Always allow from this computer”.")

    async def start(self):
        if not self.host:
            self.state = "no_host"
        elif not (self.dir / "adb_ok").exists():
            self.state = "needs_pairing"
        await super().start()

    async def _close(self):
        await self.adb_close()

    async def _connect(self):
        if not (self.dir / "adb_ok").exists():
            self.state = "needs_pairing"
            return
        try:
            await self.adb_connect(auth_timeout=10)
            self.state, self.error = "connected", ""
        except RemoteError as e:
            self.state, self.error = ("needs_pairing" if "Allow" in str(e) else "unreachable"), str(e)

    async def pair_start(self):
        if not self.host:
            raise RemoteError("Set the device address first.")
        self.state, self.error = "pairing", ""
        await self.adb_close()
        try:
            await self.adb_connect(auth_timeout=60)      # the TV shows "Allow USB debugging?"
        except RemoteError as e:
            self.state, self.error = "needs_pairing", str(e)
            raise
        self.state, self.error = "connected", ""
        return {"done": True}

    async def key(self, key, direction="SHORT"):
        self._ensure()
        await self.adb_key(key, direction)
        return "adb"

    async def text(self, text):
        self._ensure()
        await self.adb_text(text)
        return "adb"

    async def launch(self, app_id):
        self._ensure()
        await self.adb_launch(APPS[app_id]["firetv"])
        return "adb"

    def _ensure(self):
        if self.state != "connected" or self.adb is None:
            if self.state == "connected":
                self.state = "unreachable"
                self.poke()
            self.require_connected()

    def info(self):
        return {}


# ======================================================================================
class AppleTVRemote(BaseRemote):
    kind = "appletv"
    unsupported = {"VOLUME_MUTE", "SEARCH", "DEL", "ENTER", "CAPTIONS", "PROG_RED", "PROG_GREEN", "PROG_YELLOW", "PROG_BLUE", "INFO"}
    pairing_help = ("Press “Start pairing”: a 4-digit PIN appears on the Apple TV (you'll see it in the picture). Type it here. "
                    "Apple TV may ask twice (AirPlay, then Companion) — just enter each PIN.")

    def __init__(self, port, data_dir, store):
        super().__init__(port, data_dir, store)
        try:
            self.creds = json.loads(port.get("creds") or "{}")
        except ValueError:
            self.creds = {}
        self.atv = None
        self.conf = None
        self._pair_queue = []
        self._pairing = None

    async def _scan(self):
        import pyatv
        loop = asyncio.get_running_loop()
        found = await pyatv.scan(loop, hosts=[self.host], timeout=5)
        if not found:
            raise RemoteError(f"No Apple TV answered at {self.host}.")
        conf = found[0]
        from pyatv.const import Protocol
        for name, proto in (("airplay", Protocol.AirPlay), ("companion", Protocol.Companion), ("mrp", Protocol.MRP)):
            if self.creds.get(name) and conf.get_service(proto):
                conf.set_credentials(proto, self.creds[name])
        self.conf = conf
        return conf

    def _needs(self, conf):
        """Protocols that still need pairing (in order)."""
        from pyatv.const import PairingRequirement, Protocol
        out = []
        for name, proto in (("airplay", Protocol.AirPlay), ("companion", Protocol.Companion)):
            svc = conf.get_service(proto)
            if svc and not self.creds.get(name) and svc.pairing != PairingRequirement.NotNeeded:
                out.append((name, proto))
        return out

    async def _close(self):
        if self.atv:
            try:
                self.atv.close()
            except Exception:  # noqa: BLE001
                pass
        self.atv = None
        if self._pairing:
            try:
                await self._pairing.close()
            except Exception:  # noqa: BLE001
                pass
            self._pairing = None

    async def _connect(self):
        import pyatv
        conf = await self._scan()
        if self._needs(conf):
            self.state = "needs_pairing"
            return
        try:
            atv = await pyatv.connect(conf, asyncio.get_running_loop())
        except pyatv.exceptions.AuthenticationError:
            # e.g. after a tvOS update/reset, or TanchTV was removed under Remotes and Devices
            self.state = "needs_pairing"
            self.error = "The Apple TV no longer accepts TanchTV's pairing (updated or reset?). Pair again."
            return
        remote = self

        class _L:
            def connection_lost(self, exc):
                remote.state, remote.error = "unreachable", f"Connection lost: {exc}"
                remote.poke()

            def connection_closed(self):
                if remote.state == "connected":
                    remote.state = "unreachable"
                    remote.poke()

        atv.listener = _L()
        self.atv, self.state, self.error = atv, "connected", ""

    async def pair_start(self):
        import pyatv
        if not self.host:
            raise RemoteError("Set the device address first.")
        await self._close()
        self.state, self.error = "pairing", ""
        # Always pair from scratch: with old credentials attached the Apple TV treats us as already
        # paired and never shows a PIN (and an update/reset may have invalidated them anyway).
        self.creds = {}
        self.store({"creds": "{}"})
        conf = await self._scan()
        self._pair_queue = self._needs_all(conf)
        if not self._pair_queue:
            self.state = "starting"
            self.poke()
            return {"done": True}
        return await self._begin_next(pyatv)

    def _needs_all(self, conf):
        from pyatv.const import Protocol
        return [(n, p) for n, p in (("airplay", Protocol.AirPlay), ("companion", Protocol.Companion)) if conf.get_service(p)]

    async def _begin_next(self, pyatv):
        name, proto = self._pair_queue[0]
        self._pairing = await pyatv.pair(self.conf, proto, asyncio.get_running_loop(), name="TanchTV")
        await self._pairing.begin()
        step = f" (step {len(self._needs_all(self.conf)) - len(self._pair_queue) + 1} of {len(self._needs_all(self.conf))})"
        return {"prompt": f"Type the PIN shown on the Apple TV{step}.", "code": True, "step": name}

    async def pair_finish(self, code):
        import pyatv
        if not self._pairing:
            raise RemoteError("Start pairing first.")
        name, _ = self._pair_queue[0]
        self._pairing.pin(code.strip())
        try:
            await self._pairing.finish()
        except Exception as e:  # noqa: BLE001
            await self._close()
            self.state, self.error = "needs_pairing", f"Pairing failed: {e}"
            raise RemoteError("Wrong PIN or pairing cancelled. Start again.") from e
        if not self._pairing.has_paired:
            await self._close()
            self.state = "needs_pairing"
            raise RemoteError("Pairing didn't complete. Start again.")
        self.creds[name] = self._pairing.service.credentials
        self.store({"creds": json.dumps(self.creds)})
        await self._pairing.close()
        self._pairing = None
        self._pair_queue.pop(0)
        if self._pair_queue:
            return await self._begin_next(pyatv)
        self.state = "starting"
        self.poke()
        return {"done": True}

    def _proto(self, iface, proto):
        try:
            return iface.get(proto)
        except Exception:  # noqa: BLE001
            return None

    def _mrp(self, iface):
        from pyatv.const import Protocol
        return self._proto(iface, Protocol.MRP)

    def _power_state(self):
        """True/False/None. The protocols disagree for a while after a change (Companion still says Off
        right after waking; MRP said Off while awake once), so: on if any says On, off if all say Off."""
        from pyatv.const import PowerState, Protocol
        states = []
        for proto in (Protocol.Companion, Protocol.MRP):
            pw = self._proto(self.atv.power, proto)
            try:
                if pw is not None and pw.power_state in (PowerState.On, PowerState.Off):
                    states.append(pw.power_state == PowerState.On)
            except Exception:  # noqa: BLE001
                pass
        if not states:
            return None
        return any(states)

    async def _power_sleep(self):
        """tvOS 26: Companion's HID Sleep works. Older tvOS (15) rejects it ('_hidC failed'); there,
        hold Home opens a panel with Sleep focused, so wait for it and press Select (over MRP)."""
        from pyatv.const import InputAction, Protocol
        pw = self._proto(self.atv.power, Protocol.Companion)
        if pw is not None:
            try:
                await pw.turn_off()
                return
            except Exception as e:  # noqa: BLE001
                log.info("Apple TV %s: Companion sleep failed (%s), using Home-hold fallback", self.host, e)
        rc = self._mrp(self.atv.remote_control)
        if rc is None:
            await self.atv.power.turn_off()
            return
        await rc.home(InputAction.Hold)
        await asyncio.sleep(1.5)
        await rc.select()

    async def _power_wake(self):
        """The wake command alone may leave HDMI off after a longer sleep (the box says On, the capture
        card still shows no signal). A button press always brings the picture back, and the first
        press on a sleeping Apple TV only wakes it, like the physical remote. So: wake, then Home."""
        from pyatv.const import Protocol
        for pw in (self._proto(self.atv.power, Protocol.Companion), self._mrp(self.atv.power), self.atv.power):
            if pw is None:
                continue
            try:
                await pw.turn_on()
                break
            except Exception as e:  # noqa: BLE001
                log.info("Apple TV %s: wake failed over one protocol (%s), trying the next", self.host, e)
        await asyncio.sleep(1)
        for rc in (self._proto(self.atv.remote_control, Protocol.Companion), self._mrp(self.atv.remote_control)):
            if rc is None:
                continue
            try:
                await rc.home()
                return
            except Exception as e:  # noqa: BLE001
                log.info("Apple TV %s: Home press failed (%s)", self.host, e)

    async def key(self, key, direction="SHORT"):
        from pyatv.const import InputAction
        self.require_connected()
        if key in self.unsupported:
            raise RemoteError("Apple TV has no such button.")
        try:
            return await self._key(self._mrp(self.atv.remote_control) or self.atv.remote_control, key, direction, InputAction)
        except RemoteError:
            raise
        except Exception:  # noqa: BLE001  MRP failed: try whatever pyatv picks (Companion)
            if self._mrp(self.atv.remote_control) is None:
                raise
            return await self._key(self.atv.remote_control, key, direction, InputAction)

    async def _key(self, rc, key, direction, InputAction):
        if direction == "END_LONG":
            return "atv"
        hold = InputAction.Hold if direction == "START_LONG" else InputAction.SingleTap
        simple = {"DPAD_UP": rc.up, "DPAD_DOWN": rc.down, "DPAD_LEFT": rc.left, "DPAD_RIGHT": rc.right,
                  "MEDIA_PLAY_PAUSE": rc.play_pause, "MEDIA_NEXT": rc.next, "MEDIA_PREVIOUS": rc.previous,
                  "MEDIA_STOP": rc.stop, "MEDIA_FAST_FORWARD": rc.skip_forward, "MEDIA_REWIND": rc.skip_backward,
                  "VOLUME_UP": rc.volume_up, "VOLUME_DOWN": rc.volume_down, "CHANNEL_UP": rc.channel_up,
                  "CHANNEL_DOWN": rc.channel_down, "GUIDE": rc.guide, "MENU": rc.top_menu}
        if key in ("DPAD_CENTER",):
            await rc.select(action=hold)
        elif key == "BACK":
            await rc.menu(action=hold)
        elif key == "HOME":
            await (rc.home_hold() if direction == "START_LONG" else rc.home())
        elif key in ("POWER",):
            await (self._power_sleep() if self._power_state() is not False else self._power_wake())
        elif key == "WAKEUP":
            await self._power_wake()
        elif key == "SLEEP":
            await self._power_sleep()
        elif key == "SETTINGS":
            await self.atv.apps.launch_app("com.apple.TVSettings")
        elif key in simple:
            await simple[key]()
        else:
            raise RemoteError("Apple TV has no such button.")
        return "atv"

    async def text(self, text):
        self.require_connected()
        try:
            await self.atv.keyboard.text_set(text)
        except Exception as e:  # noqa: BLE001
            raise RemoteError("Select a text field on the Apple TV first.") from e
        return "atv"

    async def launch(self, app_id):
        self.require_connected()
        await self.atv.apps.launch_app(APPS[app_id]["appletv"])
        return "atv"

    def info(self):
        d = {}
        if self.state == "connected" and self.atv:
            try:
                on = self._power_state()
                if on is not None:
                    d["is_on"] = on
            except Exception:  # noqa: BLE001
                pass
            try:
                d["device"] = {"manufacturer": "Apple", "model": str(self.atv.device_info.model_str), "sw_version": self.atv.device_info.version}
            except Exception:  # noqa: BLE001
                pass
        return d


DRIVERS = {"androidtv": AndroidTVRemote, "firetv": FireTVRemote, "appletv": AppleTVRemote}


# ======================================================================================
class Remotes:
    """One driver per port."""

    def __init__(self, data_root: Path, store):
        self.root = data_root
        self.store = store          # store(port_id, fields: dict)
        self.r: dict[int, BaseRemote] = {}

    async def add(self, port: dict):
        await self.remove(port["id"])
        cls = DRIVERS.get(port["kind"])
        if not cls:
            return
        drv = cls(port, self.root / str(port["id"]), lambda fields, pid=port["id"]: self.store(pid, fields))
        self.r[port["id"]] = drv
        try:
            await drv.start()
        except Exception as e:  # noqa: BLE001
            drv.state, drv.error = "error", f"{type(e).__name__}: {e}"

    async def remove(self, port_id: int):
        drv = self.r.pop(port_id, None)
        if drv:
            await drv.stop()

    def get(self, port_id: int) -> BaseRemote | None:
        return self.r.get(port_id)
