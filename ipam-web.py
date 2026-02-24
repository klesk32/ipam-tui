#!/usr/bin/env python3
"""
IPAM TUI Web Interface - Serves the TUI via xterm.js over WebSocket
Usage: python3 ipam-web.py <database.db> [--port 8080] [--host 0.0.0.0]
"""

import asyncio
import fcntl
import os
import pty
import signal
import struct
import sys
import termios

from aiohttp import web, WSMsgType

VERSION = "0.9.7"

# HTML template with xterm.js
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>IPAM / VLAN Manager</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { height: 100%; background: #000; overflow: hidden; }
        #terminal { height: 100%; width: 100%; }
    </style>
</head>
<body>
    <div id="terminal"></div>
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.9.0/lib/xterm-addon-web-links.js"></script>
    <script>
        const term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: '"Cascadia Code", "Fira Code", "Source Code Pro", monospace',
            theme: {
                background: '#000000',
                foreground: '#00ff00',
                cursor: '#00ff00',
                cursorAccent: '#000000',
            }
        });

        const fitAddon = new FitAddon.FitAddon();
        const webLinksAddon = new WebLinksAddon.WebLinksAddon();

        term.loadAddon(fitAddon);
        term.loadAddon(webLinksAddon);
        term.open(document.getElementById('terminal'));
        fitAddon.fit();

        let ws = null;
        let reconnectTimeout = null;

        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onopen = () => {
                // Send initial terminal size
                ws.send(JSON.stringify({
                    type: 'resize',
                    cols: term.cols,
                    rows: term.rows
                }));
            };

            ws.onmessage = (event) => {
                term.write(event.data);
            };

            ws.onclose = () => {
                term.write('\\r\\n\\x1b[33m[Session ended - Press any key to reconnect]\\x1b[0m\\r\\n');
                ws = null;
            };

            ws.onerror = (err) => {
                term.write('\\r\\n\\x1b[31m[Connection error]\\x1b[0m\\r\\n');
            };
        }

        term.onData((data) => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'input', data: data }));
            } else if (!ws || ws.readyState === WebSocket.CLOSED) {
                // Reconnect on any keypress when disconnected
                term.clear();
                connect();
            }
        });

        term.onResize((size) => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'resize',
                    cols: size.cols,
                    rows: size.rows
                }));
            }
        });

        window.addEventListener('resize', () => {
            fitAddon.fit();
        });

        // Initial connection
        connect();
        term.focus();
    </script>
</body>
</html>
"""


class PTYProcess:
    """Manages a PTY subprocess."""

    def __init__(self, cmd: list[str], cwd: str = None):
        self.cmd = cmd
        self.cwd = cwd
        self.master_fd = None
        self.pid = None

    def spawn(self, rows: int = 24, cols: int = 80):
        """Spawn the process in a PTY."""
        pid, fd = pty.fork()

        if pid == 0:
            # Child process
            if self.cwd:
                os.chdir(self.cwd)
            os.execvp(self.cmd[0], self.cmd)
        else:
            # Parent process
            self.pid = pid
            self.master_fd = fd
            self.resize(rows, cols)

    def resize(self, rows: int, cols: int):
        """Resize the PTY."""
        if self.master_fd is not None:
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)

    def write(self, data: bytes):
        """Write data to the PTY."""
        if self.master_fd is not None:
            os.write(self.master_fd, data)

    def read(self, size: int = 4096, timeout: float = 0.1) -> bytes:
        """Read data from the PTY with timeout."""
        if self.master_fd is None:
            return b''

        import select
        try:
            # Wait for data with timeout
            ready, _, _ = select.select([self.master_fd], [], [], timeout)
            if ready:
                return os.read(self.master_fd, size)
            return b''
        except (OSError, ValueError):
            # PTY closed or invalid fd
            return b''

    def is_alive(self) -> bool:
        """Check if the process is still running."""
        if self.pid is None:
            return False
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                return True  # Still running
            else:
                self.pid = None  # Mark as dead
                return False
        except (OSError, ChildProcessError):
            self.pid = None
            return False

    def terminate(self):
        """Terminate the process."""
        if self.pid is not None:
            try:
                os.kill(self.pid, signal.SIGTERM)
                os.waitpid(self.pid, 0)
            except (OSError, ChildProcessError):
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass


async def index_handler(request):
    """Serve the terminal HTML page."""
    return web.Response(text=HTML_TEMPLATE, content_type='text/html')


async def exports_list_handler(request):
    """List available export files across all sessions."""
    exports_dir = request.app['exports_dir']
    session_id = request.match_info.get('session_id')

    files = []
    sessions = []

    if os.path.exists(exports_dir):
        for entry in sorted(os.listdir(exports_dir), reverse=True):
            entry_path = os.path.join(exports_dir, entry)

            if os.path.isdir(entry_path):
                # It's a session directory - list files within
                session_files = []
                for f in os.listdir(entry_path):
                    filepath = os.path.join(entry_path, f)
                    if os.path.isfile(filepath):
                        stat = os.stat(filepath)
                        size = stat.st_size
                        mtime = stat.st_mtime
                        # Format size
                        if size < 1024:
                            size_str = f"{size} B"
                        elif size < 1024 * 1024:
                            size_str = f"{size / 1024:.1f} KB"
                        else:
                            size_str = f"{size / (1024 * 1024):.1f} MB"

                        from datetime import datetime
                        mtime_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                        session_files.append((f, size_str, mtime_str, entry))

                if session_files:
                    sessions.append((entry, session_files))

    # Generate HTML listing
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>IPAM Exports</title>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
        h1, h2 { border-bottom: 1px solid #0f0; padding-bottom: 10px; }
        h2 { font-size: 1em; color: #0a0; margin-top: 30px; }
        a { color: #0f0; }
        a:hover { color: #fff; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #333; }
        th { color: #0f0; }
        .empty { color: #666; font-style: italic; }
        .back { margin-bottom: 20px; }
        .session-id { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="back"><a href="/">← Back to Terminal</a></div>
    <h1>📁 Exports</h1>
"""

    if sessions:
        for session_id, session_files in sessions:
            html += f'    <h2>Session: <span class="session-id">{session_id}</span></h2>\n'
            html += """    <table>
        <tr><th>Filename</th><th>Size</th><th>Modified</th></tr>
"""
            for fname, size, mtime, sid in session_files:
                html += f'        <tr><td><a href="/exports/{sid}/{fname}">{fname}</a></td><td>{size}</td><td>{mtime}</td></tr>\n'
            html += "    </table>\n"
    else:
        html += '    <p class="empty">No exports yet. Use "Export All VLANs" or "Export VLAN" from the terminal.</p>\n'

    html += """</body>
</html>"""

    return web.Response(text=html, content_type='text/html')


async def exports_file_handler(request):
    """Serve an individual export file from a session directory."""
    exports_dir = request.app['exports_dir']
    session_id = request.match_info['session_id']
    filename = request.match_info['filename']

    # Security: prevent directory traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        raise web.HTTPForbidden()
    if '..' in session_id or '/' in session_id or '\\' in session_id:
        raise web.HTTPForbidden()

    filepath = os.path.join(exports_dir, session_id, filename)

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        raise web.HTTPNotFound()

    # Determine content type
    if filename.endswith('.xlsx'):
        content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    elif filename.endswith('.csv'):
        content_type = 'text/csv'
    else:
        content_type = 'application/octet-stream'

    return web.FileResponse(
        filepath,
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )


async def websocket_handler(request):
    """Handle WebSocket connections for terminal I/O."""
    import uuid
    import shutil

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    db_path = request.app['db_path']
    tui_flags = request.app.get('tui_flags', [])
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Find the TUI script in the same directory as this web server
    tui_script = os.path.join(script_dir, 'ipam-tui.py')

    if not os.path.exists(tui_script):
        await ws.send_str(f"\x1b[31mError: Could not find ipam-tui script in {script_dir}\x1b[0m\r\n")
        await ws.close()
        return ws

    # Create per-session exports directory
    exports_base = request.app['exports_dir']
    session_id = uuid.uuid4().hex[:12]
    session_exports_dir = os.path.join(exports_base, session_id)
    os.makedirs(session_exports_dir, exist_ok=True)

    # Spawn the TUI process with any additional flags, cwd set to session exports dir
    cmd = ['python3', tui_script, db_path] + tui_flags
    pty_proc = PTYProcess(cmd, cwd=session_exports_dir)

    try:
        pty_proc.spawn()
    except Exception as e:
        await ws.send_str(f"\x1b[31mError spawning process: {e}\x1b[0m\r\n")
        await ws.close()
        # Clean up empty session dir
        try:
            os.rmdir(session_exports_dir)
        except OSError:
            pass
        return ws

    stop_event = asyncio.Event()

    async def read_pty():
        """Read from PTY and send to WebSocket."""
        loop = asyncio.get_event_loop()
        while not stop_event.is_set():
            try:
                data = await loop.run_in_executor(None, pty_proc.read)
                if data:
                    if not ws.closed:
                        await ws.send_str(data.decode('utf-8', errors='replace'))
                elif not pty_proc.is_alive():
                    # No data and process is dead
                    break
            except Exception:
                break

        # Signal that we're done and close websocket
        stop_event.set()
        if not ws.closed:
            await ws.close()

    # Start reading from PTY
    read_task = asyncio.create_task(read_pty())

    try:
        async for msg in ws:
            if stop_event.is_set():
                break
            if msg.type == WSMsgType.TEXT:
                try:
                    import json
                    data = json.loads(msg.data)

                    if data.get('type') == 'input':
                        pty_proc.write(data['data'].encode('utf-8'))
                    elif data.get('type') == 'resize':
                        cols = data.get('cols', 80)
                        rows = data.get('rows', 24)
                        pty_proc.resize(rows, cols)
                except (json.JSONDecodeError, KeyError):
                    pass
                except OSError:
                    # PTY write failed, process likely dead
                    break
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        stop_event.set()
        read_task.cancel()
        try:
            await read_task
        except asyncio.CancelledError:
            pass
        pty_proc.terminate()

        # Clean up session exports directory
        try:
            shutil.rmtree(session_exports_dir)
        except OSError:
            pass

    return ws


def main():
    if "--version" in sys.argv:
        print(f"IPAM Web Server v{VERSION}")
        sys.exit(0)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <database.db> [--port 8080] [--host 0.0.0.0] [--exports-dir ./exports] [-- --bios --other-tui-flags]")
        sys.exit(1)

    db_path = None
    host = '0.0.0.0'
    port = 8080
    exports_dir = None
    tui_flags = []

    # Parse arguments
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--':
            # Everything after -- is passed to the TUI
            tui_flags = args[i + 1:]
            break
        elif args[i] == '--port' and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] == '--host' and i + 1 < len(args):
            host = args[i + 1]
            i += 2
        elif args[i] == '--exports-dir' and i + 1 < len(args):
            exports_dir = args[i + 1]
            i += 2
        elif not args[i].startswith('--'):
            db_path = args[i]
            i += 1
        else:
            i += 1

    if not db_path:
        print("Error: Database path required")
        sys.exit(1)

    if not os.path.exists(db_path):
        print(f"Note: Database '{db_path}' will be created on first connection")

    # Set up exports directory
    if exports_dir is None:
        exports_dir = os.path.join(os.path.dirname(os.path.abspath(db_path)), 'exports')
    exports_dir = os.path.abspath(exports_dir)

    if not os.path.exists(exports_dir):
        os.makedirs(exports_dir)
        print(f"Created exports directory: {exports_dir}")

    app = web.Application()
    app['db_path'] = os.path.abspath(db_path)
    app['tui_flags'] = tui_flags
    app['exports_dir'] = exports_dir

    app.router.add_get('/', index_handler)
    app.router.add_get('/ws', websocket_handler)
    app.router.add_get('/exports', exports_list_handler)
    app.router.add_get('/exports/', exports_list_handler)
    app.router.add_get('/exports/{session_id}/{filename}', exports_file_handler)

    print(f"IPAM TUI Web Interface v{VERSION}")
    print(f"Database: {db_path}")
    print(f"Exports:  {exports_dir}")
    if tui_flags:
        print(f"TUI flags: {' '.join(tui_flags)}")
    print(f"Starting server at http://{host}:{port}")
    print(f"  Terminal: http://{host}:{port}/")
    print(f"  Exports:  http://{host}:{port}/exports/")
    print(f"Press Ctrl+C to stop")

    # Set up proper signal handling for clean shutdown
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    runner = web.AppRunner(app)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, host, port)
    loop.run_until_complete(site.start())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        loop.run_until_complete(runner.cleanup())
        loop.close()
        # Clean up exports directory
        import shutil
        shutil.rmtree(exports_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
