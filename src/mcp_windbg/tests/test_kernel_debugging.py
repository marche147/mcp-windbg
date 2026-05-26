import asyncio
import os
import signal

import pytest
import mcp.types as types

from mcp_windbg.cdb_session import CDBError, CDBSession
from mcp_windbg.server import (
    CloseWindbgKernelParams,
    RunWindbgCmdParams,
    SendCtrlBreakParams,
    _create_server,
    active_sessions,
    get_or_create_session,
    unload_session,
)


class DummyStdin:
    def __init__(self):
        self.writes = []

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        pass


class DummyProcess:
    def __init__(self):
        self.stdin = DummyStdin()
        self.stdout = []
        self.signals = []
        self.terminated = False

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.terminated = True

    def send_signal(self, sig):
        self.signals.append(sig)


@pytest.fixture
def session_process(monkeypatch):
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        process = DummyProcess()
        captured["process"] = process
        return process

    monkeypatch.setattr("mcp_windbg.cdb_session.subprocess.Popen", fake_popen)
    monkeypatch.setattr(CDBSession, "_wait_for_prompt", lambda self, timeout=None: None)
    monkeypatch.setattr(CDBSession, "_read_output", lambda self: None)
    monkeypatch.setattr(os.path, "isfile", lambda path: path in {"C:\\dbg\\cdb.exe", "C:\\dbg\\kd.exe"})

    return captured


def test_kernel_connection_uses_kd_dash_k(session_process):
    session = CDBSession(
        kernel_connection="net:port=50000,key=1.2.3.4",
        break_on_connection=True,
        kd_path="C:\\dbg\\kd.exe",
        symbols_path="srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    )

    assert session_process["args"] == [
        "C:\\dbg\\kd.exe",
        "-b",
        "-k",
        "net:port=50000,key=1.2.3.4",
        "-y",
        "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    ]
    assert session.get_session_id() == "kernel:net:port=50000,key=1.2.3.4"


def test_local_kernel_uses_kd_dash_kl(session_process):
    session = CDBSession(local_kernel=True, break_on_connection=True, kd_path="C:\\dbg\\kd.exe")

    assert session_process["args"] == ["C:\\dbg\\kd.exe", "-b", "-kl"]
    assert session.get_session_id() == "kernel:local"


def test_cdb_modes_still_use_cdb(session_process):
    session = CDBSession(remote_connection="tcp:Port=5005,Server=127.0.0.1", cdb_path="C:\\dbg\\cdb.exe")

    assert session_process["args"] == [
        "C:\\dbg\\cdb.exe",
        "-remote",
        "tcp:Port=5005,Server=127.0.0.1",
    ]
    assert session.get_session_id() == "remote:tcp:Port=5005,Server=127.0.0.1"


def test_target_validation_rejects_ambiguous_session():
    with pytest.raises(ValueError, match="Exactly one debugger target must be provided"):
        CDBSession(kernel_connection="net:port=50000,key=1.2.3.4", local_kernel=True)


def test_tool_param_validation_accepts_kernel_selectors():
    assert RunWindbgCmdParams(kernel_connection="net:port=50000,key=1.2.3.4", command="vertarget")
    assert RunWindbgCmdParams(local_kernel=True, command="lm")
    assert SendCtrlBreakParams(kernel_connection="net:port=50000,key=1.2.3.4")
    assert CloseWindbgKernelParams(local_kernel=True)


def test_tool_param_validation_rejects_ambiguous_kernel_selectors():
    with pytest.raises(ValueError):
        RunWindbgCmdParams(
            connection_string="tcp:Port=5005,Server=127.0.0.1",
            kernel_connection="net:port=50000,key=1.2.3.4",
            command="r",
        )

    with pytest.raises(ValueError):
        CloseWindbgKernelParams(connection_string="net:port=50000,key=1.2.3.4", local_kernel=True)


def test_kernel_session_lifecycle(monkeypatch, session_process):
    active_sessions.clear()

    session = get_or_create_session(
        kernel_connection="net:port=50000,key=1.2.3.4",
        kd_path="C:\\dbg\\kd.exe",
    )

    assert session is active_sessions["kernel:net:port=50000,key=1.2.3.4"]
    assert unload_session(kernel_connection="net:port=50000,key=1.2.3.4")
    assert "kernel:net:port=50000,key=1.2.3.4" not in active_sessions


def test_kernel_shutdown_detaches_before_quit(session_process):
    session = CDBSession(
        kernel_connection="com:port=\\\\.\\pipe\\kd_Windows_10_x64,baud=115200,pipe,reconnect",
        kd_path="C:\\dbg\\kd.exe",
    )

    session.shutdown()

    assert session_process["process"].stdin.writes == [".detach\n", "q\n"]


def test_dump_shutdown_still_quits(monkeypatch, session_process):
    monkeypatch.setattr(os.path, "isfile", lambda path: path in {"C:\\dbg\\cdb.exe", "C:\\dumps\\test.dmp"})
    session = CDBSession(
        dump_path="C:\\dumps\\test.dmp",
        cdb_path="C:\\dbg\\cdb.exe",
    )

    session.shutdown()

    assert session_process["process"].stdin.writes == ["q\n"]


def test_kernel_session_can_defer_initial_prompt(monkeypatch, session_process):
    def timeout_wait(self, timeout=None):
        raise CDBError("Timed out waiting for debugger prompt")

    monkeypatch.setattr(CDBSession, "_wait_for_prompt", timeout_wait)

    session = CDBSession(
        kernel_connection="com:port=\\\\.\\pipe\\kd_Windows_10_x64,baud=115200,pipe,reconnect",
        defer_initial_prompt=True,
        kd_path="C:\\dbg\\kd.exe",
    )

    assert session.prompt_ready is False
    assert session.process is session_process["process"]


def test_non_kernel_session_still_requires_initial_prompt(monkeypatch, session_process):
    def timeout_wait(self, timeout=None):
        raise CDBError("Timed out waiting for debugger prompt")

    monkeypatch.setattr(CDBSession, "_wait_for_prompt", timeout_wait)

    with pytest.raises(CDBError, match="Debugger initialization timed out"):
        CDBSession(
            remote_connection="tcp:Port=5005,Server=127.0.0.1",
            cdb_path="C:\\dbg\\cdb.exe",
        )


def test_open_kernel_sends_ctrl_break_immediately(monkeypatch, session_process):
    active_sessions.clear()

    def timeout_wait(self, timeout=None):
        raise CDBError("Timed out waiting for debugger prompt")

    monkeypatch.setattr(CDBSession, "_wait_for_prompt", timeout_wait)
    monkeypatch.setattr(
        CDBSession,
        "send_command",
        lambda self, command, timeout=None: (_ for _ in ()).throw(CDBError("not ready")),
    )

    server = _create_server(kd_path="C:\\dbg\\kd.exe", timeout=1)

    async def call_open_kernel():
        list_result = await server.request_handlers[types.ListToolsRequest](None)
        assert any(tool.name == "open_windbg_kernel" for tool in list_result.root.tools)

        call_result = await server.request_handlers[types.CallToolRequest](
            types.CallToolRequest(
                params=types.CallToolRequestParams(
                    name="open_windbg_kernel",
                    arguments={
                        "connection_string": "com:port=\\\\.\\pipe\\kd_Windows_10_x64,baud=115200,pipe,reconnect",
                        "break_on_connection": True,
                        "include_basic_info": False,
                        "include_modules": False,
                    },
                )
            )
        )
        return call_result.root

    result = asyncio.run(call_open_kernel())

    assert not result.isError
    assert session_process["process"].signals == [signal.CTRL_BREAK_EVENT]
    assert result.content[0].text.startswith("Sent CTRL+BREAK to the kernel debugger session.")
    unload_session(kernel_connection="com:port=\\\\.\\pipe\\kd_Windows_10_x64,baud=115200,pipe,reconnect")
