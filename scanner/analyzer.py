"""AST-based static analyzer for LLM application security patterns.

The analyzer NEVER executes the input code. It parses Python source into an AST,
performs a lightweight forward taint pass, and reports risky source -> sink flows
as ``Finding`` objects.

Taint kinds:
    - "llm_output": value derived from an LLM response
    - "external":   value derived from external/untrusted content (web/file/RAG)
    - "secret":     value that looks like a credential/secret
    - "messages":   a list of role/content message dicts (handled at construction)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from . import rules
from .models import Finding


@dataclass
class Taint:
    kind: str
    desc: str
    line: int
    is_message_list: bool = False


def _safe_unparse(node: ast.AST, limit: int = 80) -> str:
    try:
        text = ast.unparse(node)
    except Exception:
        text = type(node).__name__
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _attr_chain(node: ast.AST) -> str:
    """Return a dotted name for an attribute/name/call/subscript chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_chain(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _attr_chain(node.func)
    if isinstance(node, ast.Subscript):
        return _attr_chain(node.value)
    return ""


def _call_name(call: ast.Call) -> str:
    return _attr_chain(call.func)


def analyze_code(source: str, filename: str = "<input>") -> list[Finding]:
    """Analyze Python source and return a list of findings."""
    return Analyzer(source, filename).run()


class Analyzer:
    def __init__(self, source: str, filename: str = "<input>"):
        self.source = source
        self.filename = filename
        self.findings: list[Finding] = []
        self.taint: dict[str, Taint] = {}
        self.func_caps: dict[str, list[str]] = {}
        self.tool_decorated: set[str] = set()
        self._seen: set[tuple] = set()

    # -- entry point --------------------------------------------------------
    def run(self) -> list[Finding]:
        try:
            tree = ast.parse(self.source)
        except SyntaxError as exc:
            return [
                Finding(
                    rule_id="parse_error",
                    owasp_category="N/A",
                    severity="low",
                    status="needs_review",
                    title="Could not parse Python source",
                    source="input code",
                    sink="ast.parse",
                    flow="syntax error",
                    reason=f"The code could not be parsed as Python: {exc.msg} (line {exc.lineno}).",
                    fix="Provide syntactically valid Python so it can be analyzed.",
                    line=exc.lineno or 0,
                    confidence="low",
                )
            ]

        self._collect_functions(tree)
        self._process_body(tree.body)
        self._detect_tools(tree)
        self.findings.sort(key=lambda f: (f.line, f.rule_id))
        return self.findings

    # -- function capability collection (for LLM06) -------------------------
    def _collect_functions(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                caps = self._function_capabilities(node)
                self.func_caps[node.name] = caps
                for dec in node.decorator_list:
                    dec_name = _attr_chain(dec if not isinstance(dec, ast.Call) else dec.func)
                    if dec_name.split(".")[-1] == "tool":
                        self.tool_decorated.add(node.name)

    def _function_capabilities(self, func: ast.AST) -> list[str]:
        caps: list[str] = []
        for n in ast.walk(func):
            if not isinstance(n, ast.Call):
                continue
            name = _call_name(n)
            parts = name.split(".")
            suffix = parts[-1]
            module = parts[0] if len(parts) > 1 else ""
            if (module == "subprocess" and suffix in rules.COMMAND_EXEC_SUFFIXES) or name.endswith("os.system"):
                caps.append(rules.CAPABILITY_DESCRIPTIONS["shell"])
            elif suffix in {"remove", "unlink", "rmtree"}:
                caps.append(rules.CAPABILITY_DESCRIPTIONS["file_delete"])
            elif name in rules.CODE_EXEC_NAMES or suffix in rules.CODE_EXEC_NAMES:
                caps.append(rules.CAPABILITY_DESCRIPTIONS["code_exec"])
            elif name.endswith("requests.post"):
                caps.append(rules.CAPABILITY_DESCRIPTIONS["network_post"])
            elif suffix == "send_email":
                caps.append(rules.CAPABILITY_DESCRIPTIONS["email"])
            elif suffix == "open" and self._open_is_write(n):
                caps.append(rules.CAPABILITY_DESCRIPTIONS["file_write"])
        # de-duplicate preserving order
        seen, ordered = set(), []
        for c in caps:
            if c not in seen:
                seen.add(c)
                ordered.append(c)
        return ordered

    @staticmethod
    def _open_is_write(call: ast.Call) -> bool:
        mode = None
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            mode = call.args[1].value
        for kw in call.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        return isinstance(mode, str) and any(m in mode for m in ("w", "a", "x", "+"))

    # -- statement processing (forward taint + inline sink detection) -------
    def _process_body(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self._process_stmt(stmt)

    def _process_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.Assign):
            self._handle_assign(stmt)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._detect_sinks(stmt.value)
            self._check_message_structure(stmt.value, stmt.lineno)
            if isinstance(stmt.target, ast.Name):
                self._assign_taint([stmt.target], stmt.value, stmt.lineno)
        elif isinstance(stmt, ast.Expr):
            self._detect_sinks(stmt.value)
            self._check_message_structure(stmt.value, stmt.lineno)
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            self._detect_sinks(stmt.value)
        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                self._detect_sinks(item.context_expr)
            self._process_body(stmt.body)
        elif isinstance(stmt, (ast.If, ast.For, ast.While)):
            # test/iter may contain sinks; bodies share module-level scope here
            test = getattr(stmt, "test", None) or getattr(stmt, "iter", None)
            if test is not None:
                self._detect_sinks(test)
            self._process_body(stmt.body)
            self._process_body(stmt.orelse)
        elif isinstance(stmt, ast.Try):
            self._process_body(stmt.body)
            for handler in stmt.handlers:
                self._process_body(handler.body)
            self._process_body(stmt.orelse)
            self._process_body(stmt.finalbody)
        # NOTE: function/class bodies are intentionally NOT descended here.
        # Dangerous calls inside functions are evaluated as agent-tool
        # capabilities (LLM06), not as standalone module-level sinks.

    def _handle_assign(self, node: ast.Assign) -> None:
        value = node.value
        self._detect_sinks(value)
        is_msg = self._check_message_structure(value, node.lineno)
        targets = [t for t in node.targets if isinstance(t, ast.Name)]
        if is_msg:
            for t in targets:
                self.taint[t.id] = Taint("messages", "messages", node.lineno, is_message_list=True)
        else:
            self._assign_taint(targets, value, node.lineno)

    def _assign_taint(self, targets, value, lineno) -> None:
        t = self._eval_taint(value)
        for tgt in targets:
            if t is not None:
                self.taint[tgt.id] = t
            elif self._is_secret_name(tgt.id):
                self.taint[tgt.id] = Taint("secret", tgt.id, lineno)

    # -- taint evaluation ---------------------------------------------------
    def _eval_taint(self, node: Optional[ast.AST]) -> Optional[Taint]:
        if node is None:
            return None

        src = self._classify_source(node)
        if src is not None:
            return src

        if isinstance(node, ast.Name):
            if node.id in self.taint:
                return self.taint[node.id]
            if self._is_secret_name(node.id):
                return Taint("secret", node.id, getattr(node, "lineno", 0))
            if any(h in node.id.lower() for h in rules.EXTERNAL_NAME_HINTS):
                return Taint("external", node.id, getattr(node, "lineno", 0))
            return None

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if self._is_secret_literal(node.value):
                return Taint("secret", _safe_unparse(node), node.lineno)
            return None

        if isinstance(node, ast.JoinedStr):  # f-string
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self._eval_taint(v.value)
                    if t is not None:
                        return t
                elif isinstance(v, ast.Constant) and isinstance(v.value, str):
                    if self._is_secret_literal(v.value):
                        return Taint("secret", _safe_unparse(v), node.lineno)
            return None

        if isinstance(node, ast.BinOp):  # string concatenation
            return self._eval_taint(node.left) or self._eval_taint(node.right)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                t = self._eval_taint(elt)
                if t is not None:
                    return t
            return None

        return None

    def _classify_source(self, node: ast.AST) -> Optional[Taint]:
        if isinstance(node, ast.Attribute):
            if node.attr == "content":
                chain = _attr_chain(node)
                if "requests" in chain:
                    return Taint("external", _safe_unparse(node), node.lineno)
                return Taint("llm_output", _safe_unparse(node), node.lineno)
            if node.attr in rules.EXTERNAL_CONTENT_ATTRS:
                return Taint("external", _safe_unparse(node), node.lineno)

        if isinstance(node, ast.Call):
            name = _call_name(node)
            suffix = name.split(".")[-1]
            if name in rules.LLM_OUTPUT_CALL_NAMES or suffix in rules.LLM_OUTPUT_CALL_SUFFIXES:
                return Taint("llm_output", _safe_unparse(node), node.lineno)
            if suffix == "run" and not name.startswith("subprocess"):
                return Taint("llm_output", _safe_unparse(node), node.lineno)
            if suffix in rules.EXTERNAL_CONTENT_CALL_SUFFIXES:
                return Taint("external", _safe_unparse(node), node.lineno)

        return None

    def _is_secret_name(self, name: str) -> bool:
        low = name.lower()
        return any(p in low for p in rules.SECRET_NAME_PATTERNS)

    def _is_secret_literal(self, value: str) -> bool:
        return any(p in value for p in rules.SECRET_LITERAL_PATTERNS)

    # -- message / prompt structure (LLM01, LLM02, LLM07) -------------------
    def _check_message_structure(self, node: ast.AST, lineno: int) -> bool:
        """Inspect a value for role/content message dicts. Returns True if it is
        a message structure (so callers can tag the variable accordingly)."""
        dicts: list[ast.Dict] = []
        if isinstance(node, (ast.List, ast.Tuple)):
            dicts = [e for e in node.elts if isinstance(e, ast.Dict)]
        elif isinstance(node, ast.Dict):
            dicts = [node]

        for d in dicts:
            role, content_node = None, None
            for k, v in zip(d.keys, d.values):
                key = k.value if isinstance(k, ast.Constant) else None
                if key == "role" and isinstance(v, ast.Constant):
                    role = v.value
                elif key == "content":
                    content_node = v
            if content_node is None:
                continue
            t = self._eval_taint(content_node)
            if t is None:
                continue
            role_label = f"message content (role={role})" if role else "message content"
            if t.kind == "secret":
                self._emit("llm02_secret_to_prompt", source=t.desc, sink=role_label, line=lineno)
                if role == "system":
                    self._emit("llm07_secret_in_system", source=t.desc,
                               sink="system prompt", line=lineno)
            elif t.kind == "external":
                self._emit("llm01_external_to_prompt", source=t.desc, sink=role_label, line=lineno)

        return len(dicts) > 0

    # -- sink detection -----------------------------------------------------
    def _detect_sinks(self, expr: ast.AST) -> None:
        for n in ast.walk(expr):
            if isinstance(n, ast.Call):
                self._classify_call_sink(n)

    def _classify_call_sink(self, call: ast.Call) -> None:
        name = _call_name(call)
        parts = name.split(".")
        suffix = parts[-1]
        module = parts[0] if len(parts) > 1 else ""
        line = call.lineno

        # 1) code execution -> LLM05
        if (isinstance(call.func, ast.Name) and name in rules.CODE_EXEC_NAMES):
            tainted = self._args_taint(call, ("llm_output", "external"))
            if tainted:
                self._emit("llm05_code_exec", source=tainted.desc,
                           sink=f"{name}(...)", line=line, status="vulnerable")
            else:
                self._emit("llm05_code_exec", source="dynamic input",
                           sink=f"{name}(...)", line=line, status="needs_review",
                           confidence="medium")
            return

        # 2) command execution -> LLM05
        if name.endswith("os.system") or (module in rules.COMMAND_EXEC_MODULES
                                          and suffix in rules.COMMAND_EXEC_SUFFIXES
                                          and module == "subprocess"):
            shell = self._has_kw_true(call, "shell")
            tainted = self._args_taint(call, ("llm_output", "external"))
            shell_str = ", shell=True" if shell else ""
            if tainted:
                self._emit("llm05_command_exec", source=tainted.desc,
                           sink=f"{name}(...{shell_str})", line=line, status="vulnerable")
            elif shell or name.endswith("os.system"):
                self._emit("llm05_command_exec", source="external/dynamic input",
                           sink=f"{name}(...{shell_str})", line=line,
                           status="needs_review", confidence="medium")
            return

        # 3) SQL execution -> LLM05 (only when tainted, to avoid noise)
        if suffix in rules.SQL_EXEC_SUFFIXES and module != "subprocess":
            tainted = self._args_taint(call, ("llm_output", "external"))
            if tainted:
                self._emit("llm05_sql_exec", source=tainted.desc,
                           sink=f"{name}(...)", line=line, status="vulnerable")
            return

        # 4) supply chain -> LLM03
        if name in rules.DESERIALIZE_CALLS:
            self._emit("llm03_deserialization", source="untrusted artifact",
                       sink=f"{name}(...)", line=line)
            return
        if self._has_kw_true(call, "trust_remote_code"):
            self._emit("llm03_remote_code", source="remote model repository",
                       sink=f"{name}(..., trust_remote_code=True)", line=line)
            # fall through is unnecessary; from_pretrained is not an LLM sink
            return

        # 5) LLM-input sink -> LLM01 / LLM02
        if self._is_llm_input(name, suffix):
            self._check_llm_call_args(call, line)

        # 6) exposure sink -> LLM02
        if suffix in rules.EXPOSURE_SUFFIXES:
            self._check_exposure(call, line)

    def _is_llm_input(self, name: str, suffix: str) -> bool:
        if any(name.endswith(s) for s in rules.LLM_INPUT_ENDSWITH):
            return True
        if name in rules.LLM_INPUT_NAMES or suffix in rules.LLM_INPUT_NAMES:
            return True
        if suffix in rules.LLM_INPUT_SUFFIXES:
            if suffix == "run" and name.startswith("subprocess"):
                return False
            return True
        return False

    def _check_llm_call_args(self, call: ast.Call, line: int) -> None:
        candidates = list(call.args)
        for kw in call.keywords:
            if kw.arg in (None, "messages", "prompt", "input", "content", "text"):
                candidates.append(kw.value)
        for arg in candidates:
            t = self._eval_taint(arg)
            if t is None or t.is_message_list:
                continue  # message lists are reported at construction time
            if t.kind == "external":
                self._emit("llm01_external_to_prompt", source=t.desc,
                           sink=f"{_call_name(call)}(...)", line=line)
            elif t.kind == "secret":
                self._emit("llm02_secret_to_prompt", source=t.desc,
                           sink=f"{_call_name(call)}(...)", line=line)

    def _check_exposure(self, call: ast.Call, line: int) -> None:
        for arg in call.args:
            t = self._eval_taint(arg)
            if t is not None and t.kind == "secret":
                self._emit("llm02_exposure", source=t.desc,
                           sink=f"{_call_name(call)}(...)", line=line)

    # -- agent tools (LLM06) ------------------------------------------------
    def _detect_tools(self, tree: ast.AST) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _call_name(n).split(".")[-1] == "Tool":
                self._inspect_tool_call(n)
        # @tool-decorated functions with dangerous capabilities
        for fname in self.tool_decorated:
            caps = self.func_caps.get(fname) or []
            if caps:
                self._emit_tool(f'@tool {fname}()', "; ".join(caps),
                                self.func_caps.get(fname, []),
                                line=0, fname=fname)

    def _inspect_tool_call(self, call: ast.Call) -> None:
        tool_name, func_name = None, None
        for kw in call.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                tool_name = kw.value.value
            elif kw.arg == "func" and isinstance(kw.value, ast.Name):
                func_name = kw.value.id
        reasons, caps = [], []
        if tool_name and tool_name.lower() in rules.DANGEROUS_TOOL_NAMES:
            reasons.append(f'tool name "{tool_name}"')
        if func_name and self.func_caps.get(func_name):
            caps = self.func_caps[func_name]
            reasons.append(f'{func_name}() performs {", ".join(caps)}')
        if reasons:
            self._emit_tool(f'agent tool "{tool_name or func_name}"',
                            "; ".join(reasons), caps, line=call.lineno)

    def _emit_tool(self, source: str, sink: str, caps: list[str], line: int,
                   fname: Optional[str] = None) -> None:
        severity = "critical" if any(
            c in caps for c in (
                rules.CAPABILITY_DESCRIPTIONS["shell"],
                rules.CAPABILITY_DESCRIPTIONS["code_exec"],
            )
        ) else "high"
        self._emit("llm06_agent_tool", source=source, sink=sink, line=line,
                   severity=severity)

    # -- helpers ------------------------------------------------------------
    def _args_taint(self, call: ast.Call, kinds: tuple[str, ...]) -> Optional[Taint]:
        for arg in list(call.args) + [kw.value for kw in call.keywords]:
            t = self._eval_taint(arg)
            if t is not None and t.kind in kinds:
                return t
        return None

    @staticmethod
    def _has_kw_true(call: ast.Call, key: str) -> bool:
        for kw in call.keywords:
            if kw.arg == key and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _emit(self, kind: str, source: str, sink: str, line: int,
              status: Optional[str] = None, severity: Optional[str] = None,
              confidence: Optional[str] = None) -> None:
        tpl = rules.TEMPLATES[kind]
        key = (kind, line, source, sink)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            Finding(
                rule_id=kind,
                owasp_category=tpl["owasp_category"],
                severity=severity or tpl["severity"],
                status=status or tpl["status"],
                title=tpl["title"],
                source=source,
                sink=sink,
                flow=f"{source} → {sink}",
                reason=tpl["reason"],
                fix=tpl["fix"],
                line=line,
                confidence=confidence or tpl["confidence"],
            )
        )
