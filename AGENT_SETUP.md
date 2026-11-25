# TanchTV: installation guide for AI agents

You are an AI coding agent (Claude Code, Codex, Antigravity, Grok, or similar) asked to install
**TanchTV** for a user. TanchTV streams HDMI capture cards to the browser and remote-controls the
TV box behind each card. This file tells you exactly what to do. Follow it in order.

## Ground rules

- **Ask before you act.** Collect every answer in Phase 1 before changing anything on the server.
  Never guess an IP address, a domain, a device or a credential. If an answer is missing, ask.
- **Secrets stay secret.** Never print, log, commit or paste into chat the admin password, the
  Google client secret, `.env`, or anything under `data/`. When you must pass a secret to a
  command, read it from the file inside the command (for example `$(grep ^TVR_PASSWORD= .env | cut -d= -f2-)`).
  If the user types a secret in chat, put it in `.env` and do not repeat it back.
- **The user does the sign-ins.** The user enters passwords, creates the passkey, and completes
  Google Cloud screens themselves. You give precise instructions and check the result.
- **Be careful on a shared server.** Other containers may run there. Never stop, remove or
  reconfigure anything that isn't TanchTV. Don't run `docker system prune` or similar.
- **Report honestly.** After each phase, tell the user what worked, what didn't, and what is next.

---

## Phase 1: Ask the user

Ask these questions (all at once is fine) and wait for the answers.

1. **Server**: where should TanchTV run? How do you reach it (for example `ssh root@192.168.1.10`),
   and in which folder should it live (for example `/opt/tanchtv`)? It must be Linux with Docker
   and Docker Compose v2. Are you already on that machine?
2. **Address**: which **https** address will people use (for example `https://tv.example.com`)?
   Which reverse proxy serves it (Nginx Proxy Manager, Caddy, Traefik, Cloudflare Tunnel...), and
   will you set up the proxy entry yourself or should I? Passkeys and Google sign-in need https.
3. **Capture cards and boxes**: how many TV boxes will you connect, and for each one:
   - the type: **Android TV / Google TV** (NVIDIA Shield, Chromecast with Google TV, ...),
     **Fire TV**, or **Apple TV**;
   - a name for it (for example "Living room Shield");
   - its IP address on your network (a DHCP reservation is strongly recommended);
   - whether its capture card is already plugged into the server (and into the box's HDMI out).
4. **Encoding**: does the server have an Intel or AMD GPU (`/dev/dri/renderD128`)? If you don't
   know, I'll check.
5. **Remote access**: will people watch only at home, or also away? Do you use a VPN such as
   Tailscale or WireGuard? (Its interface goes in `WEBRTC_INTERFACES` for the fastest path.)
6. **Google sign-in** (optional): do you want people to sign in with Google and to invite others?
   If yes, I'll guide you through Google Cloud Console in Phase 6. You'll need a Google account.
7. **First admin password**: do you want to choose it now (you'll type it into `.env` on the
   server yourself, or tell me to generate one)? It is used once; you'll replace daily use with a
   passkey.

---

## Phase 2: Check the server

Run these on the server and summarise the results for the user.

```sh
uname -a; docker --version; docker compose version
ls -l /dev/dri 2>/dev/null                       # GPU render node -> HWACCEL=vaapi
ip -br addr                                      # interface names for WEBRTC_INTERFACES
ss -ltnup 2>/dev/null | grep -E ':(8095|8555|1984|18554)\b'   # ports must be free
```

- Docker or Compose missing: stop and tell the user how to install them for their OS.
- Ports 8095, 8555, 1984 or 18554 already in use: tell the user which process holds them. 8095
  can be changed with `PORT` in `.env`; the others are go2rtc's and must be free.
- No `/dev/dri/renderD*`: plan `HWACCEL=none` (CPU encoding, about one core per port).
  Intel → `LIBVA_DRIVER_NAME=iHD` (or `i965` for very old Intel), AMD → `radeonsi`.

## Phase 3: Find the capture cards

TanchTV tells cards apart by the **USB port path** they're plugged into (for example `3-2`),
because identical dongles share vendor, product and serial numbers. List them:

```sh
for v in /sys/class/video4linux/video*; do
  [ "$(cat $v/index 2>/dev/null)" = 0 ] || continue
  usb=$(basename "$(readlink -f $v/device/..)")
  echo "$(basename $v)  usb=$usb  $(cat $v/device/../idVendor 2>/dev/null):$(cat $v/device/../idProduct 2>/dev/null)  $(cat $v/device/../product 2>/dev/null)"
done
for c in /sys/class/sound/card*; do echo "$(basename $c) id=$(cat $c/id) usb=$(basename "$(readlink -f $c/device/..)")"; done
```

- Each capture card should show up once, with a USB path, and with a sound card on the same USB
  path (that's its audio). MacroSilicon MS2109 cards are `534d:2109` ("USB Video").
- Other video devices (webcams) may appear too. Ask the user which card is connected to which box
  if it isn't obvious. Unplugging one card and listing again is a reliable way to tell.
- **Check that nothing else uses a card** (another container, a VLC instance, an OBS source):
  `fuser /dev/videoN` and `docker ps`. A card can only be opened by one program. If something
  else uses it, ask the user before stopping that program.
- Note the mapping: box name → type → IP → USB path. You'll enter it in the web UI in Phase 7.

## Phase 4: Configure and deploy

```sh
git clone https://github.com/raskitoma/tanchtv.git <folder> && cd <folder>
cp .env.example .env
cp go2rtc/go2rtc.example.yaml go2rtc/go2rtc.yaml
chmod 600 .env
```

Edit `.env` (comments inside explain each line):

- `TVR_PASSWORD`: the user's choice, or leave empty to have one generated (shown once in the logs).
- `WEBRTC_INTERFACES`: the LAN interface, plus the VPN one if any (for example `eth0,tailscale0`).
- `HWACCEL`, `VAAPI_DEVICE`, `LIBVA_DRIVER_NAME`: from Phase 2.
- `CAPTURE_*`: keep the defaults for MS2109 cards.

Start it:

```sh
docker compose up -d --build
docker compose ps
docker logs tanchtv-app 2>&1 | tail -20
```

If `TVR_PASSWORD` was empty, the log has a line "Created built-in admin ... Password: ...". Do
**not** copy it into chat: tell the user to run `docker logs tanchtv-app 2>&1 | grep "built-in admin"`
themselves, or have them set a new one with `docker exec -it tanchtv-app python cli.py admin password`.

## Phase 5: Network access

1. **Reverse proxy**: the https address from Phase 1 must forward to `http://<server-ip>:8095`
   **with WebSockets enabled**. Give the user the exact settings for their proxy (Caddy:
   `tv.example.com { reverse_proxy <server-ip>:8095 }`; Nginx Proxy Manager: new Proxy Host, scheme
   http, forward to `<server-ip>` port 8095, "Websockets Support" on, SSL certificate on).
2. **Firewall**: allow **8555/tcp and 8555/udp** from the LAN (and the VPN) to the server. That's
   WebRTC, the low-latency path. Without it everything still works through the proxy (MSE), with
   about a second more delay.
3. Check: `curl -sI https://<address>/login` returns 200.

## Phase 6: First admin, passkey and Google sign-in

Tell the user, step by step:

1. Open `https://<address>/login?admin` and sign in as **admin** with the first password.
2. **Create a passkey now.** Top right → *My account* → *Passkeys* → *Add passkey*, and confirm
   with Windows Hello / Face ID / Touch ID / phone / security key. From then on they sign in with
   *Sign in with a passkey* on the login page. **Do not skip this step.** The password is only a
   fallback that can be changed from the server's CLI. Passkeys are bound to this host name.
3. **Google sign-in** (if wanted):
   1. <https://console.cloud.google.com/> → create or pick a project.
   2. *APIs & Services → OAuth consent screen*: External; app name "TanchTV"; their email as
      support and developer contact. Publish the app, or add each person as a test user.
   3. *APIs & Services → Credentials → Create credentials → OAuth client ID → Web application*.
      Authorized redirect URI: `https://<address>/auth/google/callback` (TanchTV shows the exact
      value under *Settings → Google sign-in*).
   4. In TanchTV: *Settings → Google sign-in*: paste the **Client ID** and **Client secret**
      (the user pastes them in the browser, not in chat), set **Public URL** to
      `https://<address>`, turn it on, save.
   5. *Settings → Invites* → create one invite link per person (optionally locked to their Gmail).
      Without an invite, nobody can sign up.

## Phase 7: Add the ports and pair the boxes

For each box from Phase 3, the user goes to *Settings → Ports → + Add port*, picks the capture card
(listed by USB path), the box type, its name and IP, and saves. go2rtc restarts for a moment;
the picture appears within a few seconds. Then **Pair** on the port card opens a pop-up with the
live picture of that TV so the code can be read from anywhere:

| Box | Prepare on the box | Then |
|---|---|---|
| Android TV / Google TV | nothing | Pair → type the 6-character code. |
| Fire TV | *Settings → My Fire TV → Developer options → ADB debugging* on (no Developer options: *About* → click the name 7 times) | Connect → "Allow" on the TV, tick "Always allow". |
| Apple TV | *Settings → AirPlay and HomeKit → Allow access*: "Everyone on the same network" | Pair → type the AirPlay code, then the second code. |

Check each port: the remote chip says "Remote: connected", arrows move the TV's focus, and the
picture follows. If a box is off, the player shows the no-signal test card; that's expected.

## Phase 8: Verify and hand over

```sh
docker compose ps                                   # both "Up", app "healthy"
docker logs tanchtv-app 2>&1 | grep -iE "error|traceback" | tail
curl -s http://127.0.0.1:1984/api/streams | head -c 300; echo   # p1, p1_sd, ... present
```

Tell the user:
- the address, and that admins sign in with their passkey;
- `./data` holds the database and every pairing key: **back it up**, never share or commit it;
- how to update: `git pull && docker compose up -d --build`;
- the admin CLI (`docker exec -it tanchtv-app python cli.py ...`, see README);
- known limits: no HDCP (DRM apps may show black), no CEC, MS2109 is 1080p30 MJPEG only.

## If something goes wrong

| Symptom | Likely cause and fix |
|---|---|
| Port stays "Connecting to the TV" | `docker logs tanchtv-stream`: card not found (wrong USB path, card moved) or busy (another program has `/dev/videoN`). |
| Picture but no sound | No ALSA card on the same USB path; check `ls /sys/class/sound` and the card's cable. |
| `h264_vaapi` errors in the stream log | Wrong `LIBVA_DRIVER_NAME` / no GPU: fix it or set `HWACCEL=none`, then `docker compose up -d`. |
| Video only through the proxy (chip says "MSE") | 8555/udp+tcp blocked, or `WEBRTC_INTERFACES` misses the right interface. |
| Passkey or Google button fails | Not on https, or the Public URL / redirect URI doesn't match the address exactly. |
| Apple TV shows no PIN | Allow access setting (Phase 7), or the address belongs to a different Apple device. |
| "no longer accepts TanchTV's pairing" | The box was updated or reset: pair again. |
