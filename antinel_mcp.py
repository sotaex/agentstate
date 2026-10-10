# -*- coding: utf-8 -*-
"""Antinel MCP Server v0.1 - stdio JSON-RPC (MCP protocol)
暴露 Antinel 的核心查询能力给宿主 Agent。
协议：MCP 2.0 (stdio, newline-delimited JSON-RPC)
"""
import json, os, subprocess, sys, io

_HERE = os.path.dirname(os.path.abspath(__file__))
ANTINEL = os.path.join(_HERE, "antinel.py")
VERIFY = os.path.join(_HERE, "tools", "verify_chain.py")

TOOLS = [
    {"name": "antinel_digest", "description": "Antinel 日报：查近 N 天的操作/拦截/token 消耗（跨宿主汇总）",
     "inputSchema": {"type": "object", "properties": {
         "days": {"type": "integer", "description": "天数（默认 1）"},
         "scope": {"type": "string", "enum": ["project", "all"], "description": "范围"}},
         "required": []}},
    {"name": "antinel_verify", "description": "校验审计证据链完整性",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "antinel_host_audit", "description": "查宿主有没有偷传数据（中招报告）",
     "inputSchema": {"type": "object", "properties": {
         "host": {"type": "string", "description": "宿主名（可选）"}},
         "required": []}},
    {"name": "antinel_report", "description": "查看最近会话的详细报告",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "antinel_brief",
     "description": "决策层一页纸：数据有没有被 AI 工具带出去、比上期升还是降、"
                    "现在该做什么。★ 企业场景问 Agent 的第一句就该用这个",
     "inputSchema": {"type": "object", "properties": {
         "days": {"type": "integer", "description": "统计天数（默认 7）"}},
         "required": []}},
]

def _run(args, cwd=None, timeout=60):
    try:
        # ★ 0.35.3：MCP 服务器由宿主以**无控制台**方式拉起 ⇒ 起 python 子进程若不显式
        #   `CREATE_NO_WINDOW`，Windows 会新建控制台 = 黑窗一闪（每次 MCP 调用一次）。
        p = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return -1, "", str(e)

def exec_tool(name, args):
    root = os.getcwd()
    audit_dir = os.path.join(root, ".psl", "audit")
    if name == "antinel_digest":
        days = str((args or {}).get("days", 1))
        scope = (args or {}).get("scope", "project")
        rc, out, err = _run([sys.executable, ANTINEL, "digest", "--days", days, "--scope", scope], root)
        return out or err
    elif name == "antinel_verify":
        rc, out, err = _run([sys.executable, VERIFY, audit_dir], root)
        return out + ("\n" + err if err else "")
    elif name == "antinel_host_audit":
        host = (args or {}).get("host", "")
        cmd = [sys.executable, ANTINEL, "host-audit"]
        if host:
            cmd += ["--host", host]
        rc, out, err = _run(cmd, root)
        return out or err
    elif name == "antinel_report":
        rc, out, err = _run([sys.executable, ANTINEL, "report", "--session", "latest"], root)
        return out or err
    elif name == "antinel_brief":
        # ★ 0.34.0（E1/E5）：决策层一页纸。
        #   为什么企业 Agent 需要它：前四个工具给的都是**工程口径**（日报／链校验／
        #   单宿主中招报告／会话详情），而企业里最常问 Agent 的是
        #   「有没有出事、要不要紧、我该做什么」—— 这三个问题的答案在 brief 里。
        #   ⇒ 有了它，一个企业 Agent 才能**自己**回答"这台机器安全吗"，
        #     而不是把一堆术语原样甩给人。
        days = str((args or {}).get("days", 7))
        rc, out, err = _run([sys.executable, ANTINEL, "brief", "--days", days], root)
        return out or err
    return "Unknown tool: " + name

def main():
    """stdio JSON-RPC loop (MCP 2.0)。"""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method = req.get("method", "")
        rid = req.get("id")
        if method == "initialize":
            resp = {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "antinel", "version": "0.43.1"}}}
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name", "")
            args = params.get("arguments", {})
            text = exec_tool(name, args)
            resp = {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": text}]}}
        elif method == "ping":
            resp = {"jsonrpc": "2.0", "id": rid, "result": {}}
        else:
            resp = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
