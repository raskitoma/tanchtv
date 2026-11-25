#!/bin/sh
# TanchTV capture: one HDMI capture card -> H.264 + Opus + AAC, published to go2rtc over RTSP.
#
#   capture.sh <usb-port> <output-url>        (go2rtc calls it as:  exec:/config/capture.sh 3-2 {output})
#
# The card is found by the USB port it is plugged into (e.g. "3-2"), because identical cards
# (such as two MS2109 dongles) share vendor, product and serial. Its audio is the ALSA card that
# sits on the same USB device.
#   Opus -> WebRTC (browsers)       AAC -> MSE (Safari/iOS) and VLC links
#
# Settings (environment of the go2rtc container, see .env.example):
#   HWACCEL         vaapi (default; Intel/AMD GPU) or none (CPU, libx264)
#   VAAPI_DEVICE    /dev/dri/renderD128
#   CAPTURE_FORMAT  mjpeg        (MS2109 cards only do 1080p as MJPEG)
#   CAPTURE_SIZE    1920x1080
#   CAPTURE_FPS     30
#   VIDEO_BITRATE   5M           (VBR target; max = +1M)
USB="$1"
OUT="$2"
if [ -z "$USB" ] || [ -z "$OUT" ]; then
  echo "usage: capture.sh <usb-port> <output-url>" >&2
  exit 2
fi

HWACCEL="${HWACCEL:-vaapi}"
VAAPI_DEVICE="${VAAPI_DEVICE:-/dev/dri/renderD128}"
CAPTURE_FORMAT="${CAPTURE_FORMAT:-mjpeg}"
CAPTURE_SIZE="${CAPTURE_SIZE:-1920x1080}"
CAPTURE_FPS="${CAPTURE_FPS:-30}"
VIDEO_BITRATE="${VIDEO_BITRATE:-5M}"
GOP=$((CAPTURE_FPS * 2))

find_video() {
  for v in /sys/class/video4linux/video*; do
    [ -e "$v" ] || continue
    [ "$(cat "$v/index" 2>/dev/null)" = "0" ] || continue          # index 0 = the capture node
    if [ "$(basename "$(readlink -f "$v/device/..")")" = "$USB" ]; then echo "/dev/$(basename "$v")"; return; fi
  done
}

n=0
while V=$(find_video); [ -z "$V" ] || [ ! -e "$V" ]; do
  [ $((n % 12)) -eq 0 ] && echo "capture.sh: waiting for a capture card on USB port $USB" >&2
  n=$((n + 1)); sleep 5
done

# Audio = the ALSA card on the SAME USB device as the video.
CARD=""
for c in /sys/class/sound/card*; do
  [ -e "$c/device" ] || continue
  if [ "$(basename "$(readlink -f "$c/device/..")")" = "$USB" ]; then CARD=$(cat "$c/id"); fi
done

if [ -n "$CARD" ]; then
  echo "capture.sh: video=$V audio=hw:CARD=$CARD (usb $USB, $HWACCEL)" >&2
  set -- -thread_queue_size 1024 -f alsa -channels 2 -sample_rate 48000 -i "hw:CARD=$CARD,DEV=0"
  # ALSA stamps each USB chunk with its arrival time (a few ms of jitter). aresample=async=1 rebuilds
  # smooth sample-count timestamps (hard-correcting only past 100 ms of drift). Without it the browser's
  # WebRTC jitter buffer keeps time-stretching the audio: robotic sound and pops.
  AMAP="-map 1:a -map 1:a -af aresample=async=1:min_hard_comp=0.100000:first_pts=0 -c:a:0 libopus -b:a:0 128k -c:a:1 aac -b:a:1 160k"
else
  echo "capture.sh: video=$V WITHOUT audio (no ALSA card on usb $USB)" >&2
  set --
  AMAP="-an"
fi

MAXRATE="$(echo "$VIDEO_BITRATE" | sed 's/M$//')"
case "$MAXRATE" in (*[!0-9]*|'') MAXRATE="6M" ;; (*) MAXRATE="$((MAXRATE + 1))M" ;; esac

if [ "$HWACCEL" = "none" ]; then
  HW=""
  VENC="-map 0:v -c:v libx264 -preset veryfast -tune zerolatency -profile:v high -pix_fmt yuv420p -b:v $VIDEO_BITRATE -maxrate $MAXRATE -bufsize 1M -g $GOP -bf 0"
else
  HW="-init_hw_device vaapi=gpu:$VAAPI_DEVICE -filter_hw_device gpu"
  VENC="-map 0:v -vf format=nv12,hwupload -c:v h264_vaapi -profile:v high -rc_mode VBR -b:v $VIDEO_BITRATE -maxrate $MAXRATE -bufsize 1M -g $GOP -bf 0"
fi

# shellcheck disable=SC2086
exec ffmpeg -hide_banner -loglevel warning -nostdin $HW \
  -thread_queue_size 512 -f v4l2 -input_format "$CAPTURE_FORMAT" -video_size "$CAPTURE_SIZE" -framerate "$CAPTURE_FPS" -i "$V" \
  "$@" \
  $VENC \
  $AMAP \
  -f rtsp -rtsp_transport tcp "$OUT"
