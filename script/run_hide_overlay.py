"""
Runner cho frida_hide_overlay_agent.js — ép TYPE_APPLICATION_OVERLAY trong suốt.

Usage:
    python run_hide_overlay.py
    # Sau đó trigger overlay (bật/tắt Accessibility) — overlay sẽ KHÔNG che màn hình

Có thể chạy SONG SONG với run_trace_behind_overlay.py (cùng PID, 2 script Frida khác nhau)
— vì 1 session Frida hỗ trợ nhiều script.
"""

import subprocess
import sys
import time
from pathlib import Path

import frida
import frida_tools

PACKAGE = "com.wetpacfc9.psyfc9"
LAUNCHER = "com.igg.andr.Launcher"


def adb_pidof(pkg):
    try:
        out = subprocess.check_output(
            ['adb', 'shell', 'pidof', pkg],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        ).strip()
        return int(out.split()[0]) if out else None
    except Exception:
        return None


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')

    pid = adb_pidof(PACKAGE)
    if pid is None:
        print(f'[*] App chưa chạy — start...', file=sys.stderr)
        subprocess.run(
            ['adb', 'shell', 'am', 'start', '-n', f'{PACKAGE}/{LAUNCHER}'],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(20):
            time.sleep(0.5)
            pid = adb_pidof(PACKAGE)
            if pid:
                break
        if pid is None:
            print(f'[!] Không start được {PACKAGE}', file=sys.stderr)
            sys.exit(2)
        time.sleep(3)

    print(f'[*] Attach PID {pid}', file=sys.stderr)
    device = frida.get_usb_device(timeout=5)
    session = device.attach(pid)

    agent_js = Path(__file__).with_name('frida_hide_overlay_agent.js').read_text(encoding='utf-8')
    script = session.create_script(agent_js, runtime='v8')

    bridges_dir = Path(frida_tools.__file__).parent / 'bridges'

    def on_message(msg, data):
        if msg.get('type') == 'send':
            payload = msg.get('payload')
            if isinstance(payload, dict) and payload.get('type') == 'frida:load-bridge':
                bridge_file = bridges_dir / f'{payload["name"].lower()}.js'
                script.post({
                    'type': 'frida:bridge-loaded',
                    'filename': bridge_file.name,
                    'source': bridge_file.read_text(encoding='utf-8'),
                })
                return
            print('[agent-send]', payload, file=sys.stderr)
        elif msg.get('type') == 'error':
            print('[agent-error]', msg.get('description'), file=sys.stderr)

    script.on('message', on_message)
    script.set_log_handler(lambda level, text: print(text, flush=True))
    script.load()
    print('[*] Overlay hider active. Trigger overlay — sẽ không che màn hình.',
          file=sys.stderr)
    print('[*] Ctrl+C để dừng (overlay sẽ trở lại hoạt động bình thường).',
          file=sys.stderr)

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try: session.detach()
        except: pass


if __name__ == '__main__':
    main()
