"""Python AST-only Layer A static analyzer for PromptGuard Lite."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import rules
from .models import Finding, ScanResult, ScanSummary, build_finding_id


@dataclass(frozen=True)
class Taint:
    kind: str
    source: str
    line: int


@dataclass
class FunctionCapability:
    destructive_or_execution: list[str]
    external_side_effect: list[str]
    line: int


def _safe_unparse(node: ast.AST | None, limit: int = 140) -> str:
    if node is None:
        return ""
    try:
        text = ast.unparse(node)
    except Exception:
        text = type(node).__name__
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _attr_chain(node: ast.AST | None) -> str:
    if node is None:
        return ""
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


def _basename(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _root_name(name: str) -> str:
    return name.split(".", 1)[0] if name else ""


def _string_value(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _bool_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def scan_code(code: str, filename: str = "<memory>") -> ScanResult:
    """Scan Python source and return a Layer A ScanResult."""
    source = code.lstrip("\ufeff")
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        message = f"{exc.msg} (line {exc.lineno or 0})"
        return ScanResult(
            target=filename,
            ok=False,
            parse_error=message,
            findings=[],
            summary=ScanSummary.from_findings([]),
        )

    findings = Analyzer(source, filename, tree).run()
    summary = ScanSummary.from_findings(findings)
    return ScanResult(
        target=filename,
        ok=True,
        parse_error=None,
        findings=findings,
        summary=summary,
    )


def scan_file(path: str | Path) -> ScanResult:
    """Read a Python file with UTF-8 BOM support and scan it."""
    target = str(path)
    try:
        source = Path(path).read_text(encoding="utf-8-sig").lstrip("\ufeff")
    except OSError as exc:
        return ScanResult(
            target=target,
            ok=False,
            parse_error=str(exc),
            findings=[],
            summary=ScanSummary.from_findings([]),
        )
    return scan_code(source, target)


def analyze_code(source: str, filename: str = "<input>") -> list[Finding]:
    """Backward-compatible helper returning only findings."""
    return scan_code(source, filename).findings


class Analyzer:
    """Shallow, single-file AST taint analyzer."""

    def __init__(self, source: str, filename: str = "<memory>", tree: ast.AST | None = None):
        self.source = source
        self.filename = filename
        self.tree = tree
        self.findings: list[Finding] = []
        self.env: dict[str, list[Taint]] = {}
        self.constant_dicts: set[str] = set()
        self.safe_shell_vars: set[str] = set()
        self.system_secret_vars: set[str] = set()
        self.function_caps: dict[str, FunctionCapability] = {}
        self.decorated_tools: set[str] = set()
        self.tool_var_funcs: dict[str, set[str]] = {}
        self.tool_list_vars: dict[str, set[str]] = {}
        self.bound_tools: list[tuple[str, int, str]] = []

    def run(self) -> list[Finding]:
        tree = self.tree or ast.parse(self.source, filename=self.filename)
        self._collect_function_capabilities(tree)
        self._collect_tool_bindings(tree)
        self._process_block(getattr(tree, "body", []))
        self._emit_bound_tool_findings()
        self.findings = self._postprocess(self.findings)
        self.findings.sort(key=lambda f: (f.file, f.line, f.rule_id, f.sink))
        return self.findings

    # Statement processing -------------------------------------------------
    def _process_block(self, statements: Iterable[ast.stmt]) -> None:
        for stmt in statements:
            self._process_stmt(stmt)

    def _process_function_body(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        saved_env = dict(self.env)
        saved_safe = set(self.safe_shell_vars)
        saved_system = set(self.system_secret_vars)

        self.env = dict(self.env)
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            if self._looks_secret_name(arg.arg):
                self.env[arg.arg] = [Taint("secret", arg.arg, arg.lineno)]

        self._process_block(node.body)
        self.env = saved_env
        self.safe_shell_vars = saved_safe
        self.system_secret_vars = saved_system

    def _process_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.Assign):
            self._detect_expression(stmt.value)
            self._handle_assign(stmt.targets, stmt.value, stmt.lineno)
            return

        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._detect_expression(stmt.value)
                self._handle_assign([stmt.target], stmt.value, stmt.lineno)
            return

        if isinstance(stmt, ast.AugAssign):
            self._detect_expression(stmt.value)
            if isinstance(stmt.target, ast.Name):
                old = self.env.get(stmt.target.id, [])
                self.env[stmt.target.id] = self._unique_taints(old + self._eval_taints(stmt.value))
            return

        if isinstance(stmt, ast.Expr):
            self._detect_expression(stmt.value)
            return

        if isinstance(stmt, ast.Return):
            self._detect_expression(stmt.value)
            return

        if isinstance(stmt, ast.If):
            self._detect_expression(stmt.test)
            self._process_block(stmt.body)
            self._process_block(stmt.orelse)
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._detect_expression(stmt.iter)
            self._process_block(stmt.body)
            self._process_block(stmt.orelse)
            return

        if isinstance(stmt, ast.While):
            self._detect_expression(stmt.test)
            self._process_block(stmt.body)
            self._process_block(stmt.orelse)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self._detect_expression(item.context_expr)
                self._mark_with_optional_var(item)
            self._process_block(stmt.body)
            return

        if isinstance(stmt, ast.Try):
            self._process_block(stmt.body)
            for handler in stmt.handlers:
                self._process_block(handler.body)
            self._process_block(stmt.orelse)
            self._process_block(stmt.finalbody)
            return

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._detect_decorators(stmt)
            self._process_function_body(stmt)
            return

        if isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._process_function_body(item)
            return

    def _handle_assign(self, targets: list[ast.expr], value: ast.AST, lineno: int) -> None:
        target_names = [target.id for target in targets if isinstance(target, ast.Name)]
        taints = self._eval_taints(value)
        has_system_secret = self._contains_system_secret(value)

        for name in target_names:
            if self._is_constant_command_mapping(value):
                self.constant_dicts.add(name)
            else:
                self.constant_dicts.discard(name)

            if self._is_safe_shell_mapping_lookup(value):
                self.safe_shell_vars.add(name)
            else:
                self.safe_shell_vars.discard(name)

            assigned = list(taints)
            if self._looks_secret_name(name) and not self._is_masked_expr(value):
                assigned.append(Taint("secret", name, lineno))

            assigned = self._unique_taints(assigned)
            if assigned:
                self.env[name] = assigned
            else:
                self.env.pop(name, None)

            if self._looks_system_prompt_name(name):
                secret_taints = [t for t in assigned if t.kind == "secret"]
                if secret_taints:
                    self.system_secret_vars.add(name)
                for taint in secret_taints:
                    self._emit(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT",
                        line=lineno,
                        source=taint.source,
                        sink=name,
                        evidence=_safe_unparse(value),
                    )

            if has_system_secret:
                self.system_secret_vars.add(name)

    def _mark_with_optional_var(self, item: ast.withitem) -> None:
        if not isinstance(item.optional_vars, ast.Name):
            return
        expr = item.context_expr
        if isinstance(expr, ast.Call) and _call_name(expr) == "open":
            self.env[item.optional_vars.id] = [
                Taint("external_content", _safe_unparse(expr), getattr(expr, "lineno", 0))
            ]

    def _detect_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self._detect_expression(decorator)

    # Expression and sink detection ---------------------------------------
    def _detect_expression(self, expr: ast.AST | None) -> None:
        if expr is None:
            return
        for node in ast.walk(expr):
            if isinstance(node, ast.Dict):
                self._inspect_message_dict(node)
            elif isinstance(node, ast.Call):
                self._inspect_call(node)

    def _inspect_call(self, call: ast.Call) -> None:
        name = _call_name(call)
        suffix = _basename(name)

        if name in rules.UNSAFE_DESERIALIZATION_CALLS:
            self._emit(
                "LLM03_UNSAFE_DESERIALIZATION",
                line=call.lineno,
                source=self._first_arg_text(call) or "serialized artifact",
                sink=f"{name}(...)",
                evidence=_safe_unparse(call),
            )
            return

        if suffix == "from_pretrained" and self._has_true_keyword(call, "trust_remote_code"):
            self._emit(
                "LLM03_TRUST_REMOTE_CODE_TRUE",
                line=call.lineno,
                source="remote model",
                sink=f"{name}(..., trust_remote_code=True)",
                evidence=_safe_unparse(call),
            )
            return

        if name in rules.CODE_EXEC_CALLS:
            taint = self._first_taint(call.args, {"llm_output"})
            if taint is not None:
                self._emit(
                    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
                    line=call.lineno,
                    source=taint.source,
                    sink=f"{name}(...)",
                    evidence=_safe_unparse(call),
                )
            return

        if name in rules.SHELL_EXEC_CALLS:
            if call.args and self._is_safe_shell_command_expr(call.args[0]):
                return
            taint = self._first_taint(list(call.args) + [kw.value for kw in call.keywords], {"llm_output"})
            if taint is not None:
                self._emit(
                    "LLM05_LLM_OUTPUT_TO_SHELL",
                    line=call.lineno,
                    source=taint.source,
                    sink=f"{name}(...)",
                    evidence=_safe_unparse(call),
                )
            return

        if self._is_sql_execute_call(call):
            query_taint = self._first_taint(call.args[:1], {"llm_output"})
            if query_taint is not None:
                self._emit(
                    "LLM05_LLM_OUTPUT_TO_SQL",
                    line=call.lineno,
                    source=query_taint.source,
                    sink=f"{name}(...)",
                    evidence=_safe_unparse(call),
                )
            return

        if self._is_system_message_call(call):
            self._inspect_system_message_call(call)

        if self._is_chat_prompt_template_call(call):
            self._inspect_chat_prompt_template_call(call)

        if self._is_llm_input_call(call):
            self._inspect_llm_input_call(call)

    def _inspect_llm_input_call(self, call: ast.Call) -> None:
        candidates: list[ast.AST] = list(call.args)
        for keyword in call.keywords:
            if keyword.arg in rules.LLM_INPUT_KEYWORDS:
                candidates.append(keyword.value)

        for candidate in candidates:
            self._inspect_system_prompt_expr(candidate)
            suppress_secret = isinstance(candidate, ast.Name) and candidate.id in self.system_secret_vars
            for taint in self._eval_taints(candidate):
                if taint.kind == "external_content":
                    self._emit(
                        "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                        line=call.lineno,
                        source=taint.source,
                        sink=f"{_call_name(call)}(...)",
                        evidence=_safe_unparse(call),
                    )
                elif taint.kind == "secret" and not suppress_secret:
                    self._emit(
                        "LLM02_SECRET_TO_LLM_INPUT",
                        line=call.lineno,
                        source=taint.source,
                        sink=f"{_call_name(call)}(...)",
                        evidence=_safe_unparse(call),
                    )

    def _inspect_system_prompt_expr(self, expr: ast.AST | None) -> None:
        if expr is None:
            return
        for node in ast.walk(expr):
            if isinstance(node, ast.Dict):
                self._inspect_message_dict(node)
            elif isinstance(node, ast.Call):
                if self._is_system_message_call(node):
                    self._inspect_system_message_call(node)
                elif self._is_chat_prompt_template_call(node):
                    self._inspect_chat_prompt_template_call(node)

    def _inspect_message_dict(self, node: ast.Dict) -> bool:
        role = None
        content: ast.AST | None = None
        for key, value in zip(node.keys, node.values):
            key_text = _string_value(key)
            if key_text == "role":
                role = _string_value(value)
            elif key_text == "content":
                content = value

        if role != "system" or content is None:
            return False

        for taint in self._eval_taints(content):
            if taint.kind == "secret":
                self._emit(
                    "LLM07_SECRET_IN_SYSTEM_PROMPT",
                    line=node.lineno,
                    source=taint.source,
                    sink='{"role": "system", "content": ...}',
                    evidence=_safe_unparse(node),
                )
        return True

    def _inspect_system_message_call(self, call: ast.Call) -> bool:
        content = call.args[0] if call.args else None
        for keyword in call.keywords:
            if keyword.arg == "content":
                content = keyword.value

        emitted = False
        for taint in self._eval_taints(content):
            if taint.kind == "secret":
                self._emit(
                    "LLM07_SECRET_IN_SYSTEM_PROMPT",
                    line=call.lineno,
                    source=taint.source,
                    sink="SystemMessage(content=...)",
                    evidence=_safe_unparse(call),
                )
                emitted = True
        return emitted

    def _inspect_chat_prompt_template_call(self, call: ast.Call) -> bool:
        messages = call.args[0] if call.args else None
        emitted = False
        for content in self._iter_system_tuple_contents(messages):
            for taint in self._eval_taints(content):
                if taint.kind == "secret":
                    self._emit(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT",
                        line=getattr(content, "lineno", call.lineno),
                        source=taint.source,
                        sink='ChatPromptTemplate.from_messages(("system", ...))',
                        evidence=_safe_unparse(call),
                    )
                    emitted = True
        return emitted

    # Taint evaluation -----------------------------------------------------
    def _eval_taints(self, node: ast.AST | None) -> list[Taint]:
        if node is None or self._is_masked_expr(node):
            return []

        source = self._classify_source(node)
        if source is not None:
            return [source]

        if isinstance(node, ast.Name):
            if node.id in self.env:
                return list(self.env[node.id])
            if self._looks_secret_name(node.id):
                return [Taint("secret", node.id, getattr(node, "lineno", 0))]
            if any(hint in node.id.lower() for hint in rules.EXTERNAL_NAME_HINTS):
                return [Taint("external_content", node.id, getattr(node, "lineno", 0))]
            return []

        if isinstance(node, ast.Attribute):
            inherited = self._eval_taints(node.value)
            return inherited

        if isinstance(node, ast.Subscript):
            if self._is_safe_shell_mapping_lookup(node):
                return []
            return self._unique_taints(self._eval_taints(node.value) + self._eval_taints(node.slice))

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and self._looks_secret_literal(node.value):
                return [Taint("secret", _safe_unparse(node), node.lineno)]
            return []

        if isinstance(node, ast.JoinedStr):
            taints: list[Taint] = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    taints.extend(self._eval_taints(value.value))
                elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if self._looks_secret_literal(value.value):
                        taints.append(Taint("secret", _safe_unparse(value), node.lineno))
            return self._unique_taints(taints)

        if isinstance(node, ast.BinOp):
            return self._unique_taints(self._eval_taints(node.left) + self._eval_taints(node.right))

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            taints: list[Taint] = []
            for elt in node.elts:
                taints.extend(self._eval_taints(elt))
            return self._unique_taints(taints)

        if isinstance(node, ast.Dict):
            taints = []
            for item in list(node.keys) + list(node.values):
                taints.extend(self._eval_taints(item))
            return self._unique_taints(taints)

        if isinstance(node, ast.Call):
            if self._is_redaction_call(node):
                return []
            if self._is_string_format_call(node):
                return self._unique_taints(
                    [taint for arg in list(node.args) + [kw.value for kw in node.keywords] for taint in self._eval_taints(arg)]
                )
            return []

        return []

    def _classify_source(self, node: ast.AST) -> Taint | None:
        if isinstance(node, ast.Call):
            name = _call_name(node)
            suffix = _basename(name)
            root = _root_name(name)

            if self._is_secret_env_call(node):
                return Taint("secret", _safe_unparse(node), node.lineno)

            if name in rules.REQUESTS_CONTENT_METHODS:
                return Taint("external_content", _safe_unparse(node), node.lineno)

            if suffix == "read":
                base = getattr(node.func, "value", None)
                if self._is_open_call(base) or self._has_taint(base, {"external_content"}):
                    return Taint("external_content", _safe_unparse(node), node.lineno)

            if suffix == "read_text":
                return Taint("external_content", _safe_unparse(node), node.lineno)

            if suffix == "load" and name not in rules.UNSAFE_DESERIALIZATION_CALLS:
                if root.lower().endswith("loader") or root in rules.EXTERNAL_LOADERS or root == "loader":
                    return Taint("external_content", _safe_unparse(node), node.lineno)

            if suffix in rules.EXTERNAL_RETRIEVAL_SUFFIXES:
                return Taint("external_content", _safe_unparse(node), node.lineno)

            if self._is_llm_output_call(node):
                return Taint("llm_output", _safe_unparse(node), node.lineno)

        if isinstance(node, ast.Attribute):
            chain = _attr_chain(node)
            if self._is_secret_environ_subscript(getattr(node, "value", None)):
                return Taint("secret", _safe_unparse(node), node.lineno)

            if node.attr in {"text", "content"}:
                base = node.value
                if isinstance(base, ast.Call) and _call_name(base) in rules.REQUESTS_CONTENT_METHODS:
                    return Taint("external_content", _safe_unparse(node), node.lineno)
                if self._has_taint(base, {"external_content"}):
                    return Taint("external_content", _safe_unparse(node), node.lineno)

            if chain.endswith("output_text") or chain.endswith("choices.message.content"):
                return Taint("llm_output", _safe_unparse(node), node.lineno)

            if self._has_taint(node.value, {"llm_output"}):
                return Taint("llm_output", _safe_unparse(node), node.lineno)

        if isinstance(node, ast.Subscript) and self._is_secret_environ_subscript(node):
            return Taint("secret", _safe_unparse(node), node.lineno)

        return None

    # Classification helpers ---------------------------------------------
    def _is_llm_output_call(self, call: ast.Call) -> bool:
        name = _call_name(call)
        suffix = _basename(name)
        root = _root_name(name)
        if any(name.endswith(ending) for ending in rules.LLM_OUTPUT_CALL_ENDINGS):
            return True
        if suffix in {"invoke", "run"} and root in rules.LLM_CALL_ROOTS:
            return True
        return False

    def _is_llm_input_call(self, call: ast.Call) -> bool:
        name = _call_name(call)
        suffix = _basename(name)
        root = _root_name(name)
        if any(name.endswith(ending) for ending in rules.LLM_OUTPUT_CALL_ENDINGS):
            return True
        if suffix == "invoke":
            return True
        if suffix == "run" and root in {"chain", "agent"}:
            return True
        return False

    def _is_sql_execute_call(self, call: ast.Call) -> bool:
        name = _call_name(call)
        if _basename(name) not in rules.SQL_EXEC_SUFFIXES:
            return False
        root = _root_name(name)
        return root in rules.SQL_EXEC_ROOTS or name.endswith(".execute")

    def _is_system_message_call(self, call: ast.Call) -> bool:
        return _basename(_call_name(call)) == "SystemMessage"

    def _is_chat_prompt_template_call(self, call: ast.Call) -> bool:
        return _call_name(call).endswith("ChatPromptTemplate.from_messages")

    def _contains_system_secret(self, node: ast.AST) -> bool:
        for item in ast.walk(node):
            if isinstance(item, ast.Dict):
                role = None
                content = None
                for key, value in zip(item.keys, item.values):
                    if _string_value(key) == "role":
                        role = _string_value(value)
                    elif _string_value(key) == "content":
                        content = value
                if role == "system" and any(t.kind == "secret" for t in self._eval_taints(content)):
                    return True
            elif isinstance(item, ast.Call):
                if self._is_system_message_call(item) and self._inspectless_system_message_has_secret(item):
                    return True
                if self._is_chat_prompt_template_call(item):
                    for content in self._iter_system_tuple_contents(item.args[0] if item.args else None):
                        if any(t.kind == "secret" for t in self._eval_taints(content)):
                            return True
        return False

    def _inspectless_system_message_has_secret(self, call: ast.Call) -> bool:
        content = call.args[0] if call.args else None
        for keyword in call.keywords:
            if keyword.arg == "content":
                content = keyword.value
        return any(t.kind == "secret" for t in self._eval_taints(content))

    def _iter_system_tuple_contents(self, node: ast.AST | None) -> Iterable[ast.AST]:
        if not isinstance(node, (ast.List, ast.Tuple)):
            return []
        contents: list[ast.AST] = []
        for elt in node.elts:
            if not isinstance(elt, (ast.Tuple, ast.List)) or len(elt.elts) < 2:
                continue
            if _string_value(elt.elts[0]) == "system":
                contents.append(elt.elts[1])
        return contents

    def _is_secret_env_call(self, call: ast.Call) -> bool:
        name = _call_name(call)
        if name not in {"os.getenv", "os.environ.get"}:
            return False
        key = _string_value(call.args[0]) if call.args else None
        return bool(key and self._looks_secret_env_key(key))

    def _is_secret_environ_subscript(self, node: ast.AST | None) -> bool:
        if not isinstance(node, ast.Subscript):
            return False
        if _attr_chain(node.value) != "os.environ":
            return False
        key = _string_value(node.slice)
        return bool(key and self._looks_secret_env_key(key))

    def _looks_secret_name(self, name: str) -> bool:
        lower = name.lower()
        return any(part in lower for part in rules.SECRET_NAME_PARTS)

    def _looks_secret_env_key(self, name: str) -> bool:
        upper = name.upper()
        return any(part in upper for part in rules.SECRET_ENV_KEY_PARTS)

    def _looks_secret_literal(self, value: str) -> bool:
        lower = value.lower()
        return any(hint.lower() in lower for hint in rules.SECRET_LITERAL_HINTS)

    def _looks_system_prompt_name(self, name: str) -> bool:
        lower = name.lower()
        return lower in rules.SYSTEM_PROMPT_NAMES or lower.endswith("_system_prompt")

    def _is_masked_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.strip()
            upper = text.upper()
            if any(hint in upper for hint in rules.MASKING_HINTS):
                return True
            if len(text) >= 3 and set(text) <= {"*", "x", "X"}:
                return True
        if isinstance(node, ast.Name):
            lower = node.id.lower()
            return "redacted" in lower or "masked" in lower
        return False

    def _is_redaction_call(self, call: ast.Call) -> bool:
        name = _call_name(call).lower()
        if any(part in name for part in ("redact", "mask")):
            return True
        if name == "re.sub" and len(call.args) >= 2 and self._is_masked_expr(call.args[1]):
            return True
        return False

    def _is_string_format_call(self, call: ast.Call) -> bool:
        return _basename(_call_name(call)) == "format"

    def _is_open_call(self, node: ast.AST | None) -> bool:
        return isinstance(node, ast.Call) and _call_name(node) == "open"

    def _has_taint(self, node: ast.AST | None, kinds: set[str]) -> bool:
        return any(taint.kind in kinds for taint in self._eval_taints(node))

    def _first_taint(self, nodes: Iterable[ast.AST], kinds: set[str]) -> Taint | None:
        for node in nodes:
            for taint in self._eval_taints(node):
                if taint.kind in kinds:
                    return taint
        return None

    def _first_arg_text(self, call: ast.Call) -> str | None:
        return _safe_unparse(call.args[0]) if call.args else None

    @staticmethod
    def _has_true_keyword(call: ast.Call, name: str) -> bool:
        return any(keyword.arg == name and _bool_true(keyword.value) for keyword in call.keywords)

    @staticmethod
    def _unique_taints(taints: Iterable[Taint]) -> list[Taint]:
        seen: set[tuple[str, str, int]] = set()
        unique: list[Taint] = []
        for taint in taints:
            key = (taint.kind, taint.source, taint.line)
            if key not in seen:
                seen.add(key)
                unique.append(taint)
        return unique

    # Sanitizer helpers ----------------------------------------------------
    def _is_constant_command_mapping(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Dict):
            return False
        return all(self._is_constant_command_value(value) for value in node.values)

    def _is_constant_command_value(self, node: ast.AST | None) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, int, float, bool, type(None)))
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(self._is_constant_command_value(elt) for elt in node.elts)
        return False

    def _is_safe_shell_mapping_lookup(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.constant_dicts
        )

    def _is_safe_shell_command_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in self.safe_shell_vars:
            return True
        if self._is_safe_shell_mapping_lookup(node):
            return True
        return False

    # Agent/tool capability analysis --------------------------------------
    def _collect_function_capabilities(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            destructive: list[str] = []
            side_effects: list[str] = []
            for decorator in node.decorator_list:
                dec_name = _attr_chain(decorator.func if isinstance(decorator, ast.Call) else decorator)
                if _basename(dec_name) == "tool":
                    self.decorated_tools.add(node.name)

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                name = _call_name(child)
                if self._call_is_destructive_or_execution(name):
                    destructive.append(name)
                if self._call_is_external_side_effect(child):
                    side_effects.append(name)

            self.function_caps[node.name] = FunctionCapability(
                destructive_or_execution=self._unique_strings(destructive),
                external_side_effect=self._unique_strings(side_effects),
                line=node.lineno,
            )

    def _collect_tool_bindings(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._collect_tool_assignment(node)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_agent_binding_call(node):
                for func_name in self._extract_bound_tool_functions(node):
                    self.bound_tools.append((func_name, node.lineno, f"{_call_name(node)}(...)"))

    def _collect_tool_assignment(self, node: ast.Assign) -> None:
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if not names:
            return

        if isinstance(node.value, ast.Call):
            funcs = self._resolve_tool_expr(node.value)
            for name in names:
                if funcs:
                    self.tool_var_funcs[name] = set(funcs)
            return

        if isinstance(node.value, (ast.List, ast.Tuple)):
            funcs: set[str] = set()
            for elt in node.value.elts:
                funcs.update(self._resolve_tool_expr(elt))
            for name in names:
                if funcs:
                    self.tool_list_vars[name] = funcs

    def _resolve_tool_expr(self, node: ast.AST) -> set[str]:
        if isinstance(node, ast.Name):
            if node.id in self.tool_var_funcs:
                return set(self.tool_var_funcs[node.id])
            if node.id in self.decorated_tools:
                return {node.id}
            return set()

        if isinstance(node, ast.Call):
            name = _call_name(node)
            basename = _basename(name)
            if name.endswith(tuple(rules.TOOL_FACTORY_SUFFIXES)) or basename in rules.TOOL_CONSTRUCTOR_NAMES:
                func = self._extract_tool_function_name(node)
                return {func} if func else set()

        return set()

    def _extract_tool_function_name(self, call: ast.Call) -> str | None:
        for keyword in call.keywords:
            if keyword.arg in {"func", "coroutine"} and isinstance(keyword.value, ast.Name):
                return keyword.value.id
        for arg in call.args:
            if isinstance(arg, ast.Name):
                return arg.id
        return None

    def _is_agent_binding_call(self, call: ast.Call) -> bool:
        name = _call_name(call)
        basename = _basename(name)
        return basename in rules.AGENT_BINDING_CALLS or name.endswith("AgentExecutor.from_agent_and_tools")

    def _extract_bound_tool_functions(self, call: ast.Call) -> set[str]:
        funcs: set[str] = set()
        candidates: list[ast.AST] = list(call.args)
        for keyword in call.keywords:
            if keyword.arg in {"tools", "toolkit"}:
                candidates.append(keyword.value)

        for candidate in candidates:
            if isinstance(candidate, ast.Name):
                funcs.update(self.tool_list_vars.get(candidate.id, set()))
                funcs.update(self.tool_var_funcs.get(candidate.id, set()))
                if candidate.id in self.decorated_tools:
                    funcs.add(candidate.id)
            elif isinstance(candidate, (ast.List, ast.Tuple)):
                for elt in candidate.elts:
                    funcs.update(self._resolve_tool_expr(elt))
        return funcs

    def _emit_bound_tool_findings(self) -> None:
        emitted: set[tuple[str, str, int]] = set()
        for func_name, line, sink in self.bound_tools:
            caps = self.function_caps.get(func_name)
            if caps is None:
                continue
            if caps.destructive_or_execution:
                key = ("LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION", func_name, line)
                if key not in emitted:
                    emitted.add(key)
                    self._emit(
                        "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
                        line=line,
                        source=f"{func_name}(): {', '.join(caps.destructive_or_execution)}",
                        sink=sink,
                        evidence=f"tool {func_name} is bound to an agent",
                    )
            if caps.external_side_effect:
                key = ("LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT", func_name, line)
                if key not in emitted:
                    emitted.add(key)
                    self._emit(
                        "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
                        line=line,
                        source=f"{func_name}(): {', '.join(caps.external_side_effect)}",
                        sink=sink,
                        evidence=f"tool {func_name} is bound to an agent",
                    )

    def _call_is_destructive_or_execution(self, name: str) -> bool:
        if name in rules.DESTRUCTIVE_OR_EXECUTION_CALLS:
            return True
        if _basename(name) == "unlink":
            return True
        return False

    def _call_is_external_side_effect(self, call: ast.Call) -> bool:
        name = _call_name(call)
        if name in rules.EXTERNAL_SIDE_EFFECT_CALLS or _basename(name) == "sendmail":
            return True
        if self._is_sql_execute_call(call):
            sql_text = self._sql_literal_text(call)
            if sql_text is None:
                return False
            return sql_text.strip().lower().startswith(rules.SQL_WRITE_VERBS)
        return False

    def _sql_literal_text(self, call: ast.Call) -> str | None:
        if not call.args:
            return None
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
        if isinstance(first, ast.JoinedStr):
            parts = [value.value for value in first.values if isinstance(value, ast.Constant) and isinstance(value.value, str)]
            return "".join(parts)
        return None

    @staticmethod
    def _unique_strings(values: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    # Finding output -------------------------------------------------------
    def _emit(
        self,
        rule_id: str,
        line: int,
        source: str,
        sink: str,
        evidence: str,
        confidence: float | None = None,
    ) -> None:
        rule = rules.get_rule(rule_id)
        finding = Finding(
            finding_id=build_finding_id(self.filename, rule_id, line, sink, source),
            rule_id=rule.rule_id,
            category=rule.category,
            status=rule.status,
            severity=rule.severity,
            file=self.filename,
            line=line,
            source_kind=rule.source_kind,
            source=source,
            sink_kind=rule.sink_kind,
            sink=sink,
            flow=f"{source} -> {sink}",
            evidence=evidence,
            confidence=confidence if confidence is not None else rules.DEFAULT_CONFIDENCE[rule_id],
        )
        self.findings.append(finding)

    @staticmethod
    def _postprocess(findings: list[Finding]) -> list[Finding]:
        deduped: list[Finding] = []
        seen: set[tuple[str, str, int, str]] = set()
        for finding in findings:
            key = (finding.file, finding.rule_id, finding.line, finding.sink)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)

        llm07_sources = {
            (finding.file, finding.source)
            for finding in deduped
            if finding.rule_id == "LLM07_SECRET_IN_SYSTEM_PROMPT"
        }
        result: list[Finding] = []
        for finding in deduped:
            if (
                finding.rule_id == "LLM02_SECRET_TO_LLM_INPUT"
                and (finding.file, finding.source) in llm07_sources
                and "system" in finding.evidence.lower()
            ):
                continue
            result.append(finding)

        llm07_findings = [
            finding for finding in result
            if finding.rule_id == "LLM07_SECRET_IN_SYSTEM_PROMPT"
        ]
        suppressed_llm07_ids: set[str] = set()
        for finding in llm07_findings:
            if Analyzer._llm07_specificity(finding) > 0:
                continue
            for other in llm07_findings:
                if finding is other:
                    continue
                if finding.file != other.file or finding.source != other.source:
                    continue
                if Analyzer._llm07_specificity(other) <= Analyzer._llm07_specificity(finding):
                    continue
                if finding.sink and finding.sink in other.evidence:
                    suppressed_llm07_ids.add(finding.finding_id)
                    break

        return [
            finding for finding in result
            if finding.finding_id not in suppressed_llm07_ids
        ]

    @staticmethod
    def _llm07_specificity(finding: Finding) -> int:
        sink = finding.sink.lower()
        if sink.isidentifier():
            return 0
        if "role" in sink or "systemmessage" in sink or "chatprompttemplate" in sink:
            return 2
        if "system" in sink:
            return 1
        return 0
