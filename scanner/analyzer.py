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
    # Upper bound imposed by source provenance. Rule defaults still decide the
    # emitted confidence, so exact evidence does not promote every flow to 0.9.
    confidence_cap: float = 0.9


@dataclass
class FunctionCapability:
    destructive_or_execution: list[str]
    external_side_effect: list[str]
    line: int


@dataclass(frozen=True)
class RoleEvidence:
    role: str
    confidence_cap: float = 0.9


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


def _endswith_segments(name: str, ending: tuple[str, ...]) -> bool:
    parts = tuple(part for part in name.split(".") if part)
    return len(parts) >= len(ending) and parts[-len(ending) :] == ending


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
        self.roles: dict[str, dict[str, float]] = {}
        self.constant_dicts: set[str] = set()
        self.safe_shell_vars: set[str] = set()
        self.privileged_secrets: dict[str, set[tuple[str, str, int]]] = {}
        self.nonprivileged_secrets: dict[str, set[tuple[str, str, int]]] = {}
        self.module_aliases: dict[str, str] = {}
        self.symbol_aliases: dict[str, str] = {}
        self.function_caps: dict[str, FunctionCapability] = {}
        self.decorated_tools: set[str] = set()
        self.tool_var_funcs: dict[str, set[str]] = {}
        self.tool_list_vars: dict[str, set[str]] = {}
        self.bound_tools: list[tuple[str, int, str]] = []

    def run(self) -> list[Finding]:
        tree = self.tree or ast.parse(self.source, filename=self.filename)
        self._collect_import_aliases(tree)
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
        saved_roles = {key: dict(value) for key, value in self.roles.items()}
        saved_constant = set(self.constant_dicts)
        saved_safe = set(self.safe_shell_vars)
        saved_privileged = {key: set(value) for key, value in self.privileged_secrets.items()}
        saved_nonprivileged = {
            key: set(value) for key, value in self.nonprivileged_secrets.items()
        }

        self.env = dict(self.env)
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            if self._looks_secret_name(arg.arg):
                self.env[arg.arg] = [Taint("secret", arg.arg, arg.lineno, 0.6)]

        self._process_block(node.body)
        self.env = saved_env
        self.roles = saved_roles
        self.constant_dicts = saved_constant
        self.safe_shell_vars = saved_safe
        self.privileged_secrets = saved_privileged
        self.nonprivileged_secrets = saved_nonprivileged

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
            key = self._canonical_key(stmt.target)
            if key is not None:
                old = self.env.get(key, [])
                self.env[key] = self._unique_taints(old + self._eval_taints(stmt.value))
                privileged, nonprivileged = self._secret_usage(stmt.value)
                if privileged:
                    self.privileged_secrets.setdefault(key, set()).update(privileged)
                if nonprivileged:
                    self.nonprivileged_secrets.setdefault(key, set()).update(
                        nonprivileged
                    )
                if isinstance(stmt.op, ast.BitOr):
                    self._invalidate_safe_mapping(key)
            return

        if isinstance(stmt, ast.Expr):
            self._detect_expression(stmt.value)
            return

        if isinstance(stmt, ast.Return):
            self._detect_expression(stmt.value)
            return

        if isinstance(stmt, ast.If):
            self._detect_expression(stmt.test)
            self._bind_named_expressions(stmt.test)
            self._process_block(stmt.body)
            self._process_block(stmt.orelse)
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._detect_expression(stmt.iter)
            self._bind_target(
                stmt.target,
                self._eval_taints(stmt.iter),
                self._roles_for_expr(stmt.iter),
                *self._secret_usage(stmt.iter),
                lineno=stmt.lineno,
            )
            self._process_block(stmt.body)
            self._process_block(stmt.orelse)
            return

        if isinstance(stmt, ast.While):
            self._detect_expression(stmt.test)
            self._bind_named_expressions(stmt.test)
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

        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                self._handle_delete_target(target)
            return

        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
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
        taints = self._eval_taints(value)
        roles = self._infer_roles(value)
        privileged, nonprivileged = self._secret_usage(value)

        for target in targets:
            if isinstance(target, (ast.Tuple, ast.List)) and isinstance(
                value, (ast.Tuple, ast.List)
            ):
                for child_target, child_value in zip(target.elts, value.elts):
                    self._bind_target(
                        child_target,
                        self._eval_taints(child_value),
                        self._infer_roles(child_value),
                        *self._secret_usage(child_value),
                        lineno=lineno,
                    )
                continue
            self._bind_target(
                target,
                taints,
                roles,
                privileged,
                nonprivileged,
                lineno=lineno,
                value=value,
            )

    def _bind_target(
        self,
        target: ast.AST,
        taints: Iterable[Taint],
        roles: Iterable[RoleEvidence],
        privileged: set[tuple[str, str, int]],
        nonprivileged: set[tuple[str, str, int]],
        *,
        lineno: int,
        value: ast.AST | None = None,
    ) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self._bind_target(
                    child,
                    taints,
                    roles,
                    privileged,
                    nonprivileged,
                    lineno=lineno,
                    value=value,
                )
            return

        key = self._canonical_key(target)
        if key is None:
            return

        assigned = list(taints)
        last_segment = key.rsplit(".", 1)[-1]
        if (
            self._looks_secret_name(last_segment)
            and not any(taint.kind == "secret" for taint in assigned)
            and not (value is not None and self._is_masked_expr(value))
        ):
            assigned.append(Taint("secret", key, lineno, 0.6))
        assigned = self._unique_taints(assigned)
        if assigned:
            self.env[key] = assigned
        else:
            self.env.pop(key, None)

        role_map: dict[str, float] = {}
        for role in roles:
            role_map[role.role] = max(role_map.get(role.role, 0.0), role.confidence_cap)
        if role_map:
            self.roles[key] = role_map
        else:
            self.roles.pop(key, None)

        if privileged:
            self.privileged_secrets[key] = set(privileged)
        else:
            self.privileged_secrets.pop(key, None)
        if nonprivileged:
            self.nonprivileged_secrets[key] = set(nonprivileged)
        else:
            self.nonprivileged_secrets.pop(key, None)

        if self._looks_system_prompt_name(last_segment):
            secret_taints = [taint for taint in assigned if taint.kind == "secret"]
            identities = {self._taint_identity(taint) for taint in secret_taints}
            self.privileged_secrets[key] = identities
            self.nonprivileged_secrets.pop(key, None)
            for taint in secret_taints:
                self._emit(
                    "LLM07_SECRET_IN_SYSTEM_PROMPT",
                    line=lineno,
                    source=taint.source,
                    sink=key,
                    evidence=_safe_unparse(value),
                    confidence=self._confidence_for_taint(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT", taint
                    ),
                )

        if isinstance(target, ast.Name):
            if value is not None and self._is_constant_command_mapping(value):
                self.constant_dicts.add(key)
            else:
                self.constant_dicts.discard(key)
            if value is not None and self._is_safe_shell_mapping_lookup(value):
                self.safe_shell_vars.add(key)
            else:
                self.safe_shell_vars.discard(key)
        elif isinstance(target, ast.Subscript):
            base_key = self._canonical_key(target.value)
            if base_key is not None:
                self._invalidate_safe_mapping(base_key)
                self._merge_container_taints(base_key, assigned)
                if privileged:
                    self.privileged_secrets.setdefault(base_key, set()).update(
                        privileged
                    )
                if nonprivileged:
                    self.nonprivileged_secrets.setdefault(base_key, set()).update(
                        nonprivileged
                    )

    def _bind_named_expressions(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self._handle_assign([child.target], child.value, child.lineno)

    def _mark_with_optional_var(self, item: ast.withitem) -> None:
        if item.optional_vars is None:
            return
        expr = item.context_expr
        if isinstance(expr, ast.Call) and self._resolved_call_name(expr) == "open":
            self._bind_target(
                item.optional_vars,
                [Taint("external_content", _safe_unparse(expr), getattr(expr, "lineno", 0))],
                [],
                set(),
                set(),
                lineno=getattr(expr, "lineno", 0),
            )

    def _detect_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self._detect_expression(decorator)

    # Local name, role, and identity tracking -----------------------------
    def _collect_import_aliases(self, tree: ast.AST) -> None:
        """Collect only aliases declared by imports visible in this file."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.module_aliases[alias.asname] = alias.name
                    else:
                        root = alias.name.split(".", 1)[0]
                        self.module_aliases[root] = root
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local_name = alias.asname or alias.name
                    self.symbol_aliases[local_name] = f"{node.module}.{alias.name}"

    def _resolve_name(self, name: str) -> str:
        if not name:
            return ""
        parts = name.split(".")
        replacement = self.symbol_aliases.get(parts[0]) or self.module_aliases.get(parts[0])
        if replacement:
            return ".".join(replacement.split(".") + parts[1:])
        return name

    def _resolved_call_name(self, call: ast.Call) -> str:
        return self._resolve_name(_call_name(call))

    def _resolved_attr_chain(self, node: ast.AST | None) -> str:
        return self._resolve_name(_attr_chain(node))

    def _canonical_key(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._canonical_key(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Subscript):
            base = self._canonical_key(node.value)
            if base is None:
                return None
            value = node.slice
            if isinstance(value, ast.Constant) and isinstance(
                value.value, (str, int)
            ):
                return f"{base}[{value.value!r}]"
        return None

    def _receiver_last_segment(self, call: ast.Call) -> str:
        if not isinstance(call.func, ast.Attribute):
            return ""
        receiver = self._canonical_key(call.func.value)
        if receiver is None:
            receiver = self._resolved_attr_chain(call.func.value)
        if not receiver:
            return ""
        clean = receiver.rsplit("[", 1)[0]
        return clean.rsplit(".", 1)[-1]

    def _roles_for_expr(self, node: ast.AST | None) -> list[RoleEvidence]:
        if node is None:
            return []
        key = self._canonical_key(node)
        if key is not None and key in self.roles:
            return [
                RoleEvidence(role, cap)
                for role, cap in sorted(self.roles[key].items())
            ]
        if isinstance(node, ast.Call):
            return self._infer_roles(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._infer_roles(node)
        if key is not None:
            last = key.rsplit(".", 1)[-1].rsplit("[", 1)[0]
            fallback = rules.ROLE_NAME_FALLBACKS.get(last)
            if fallback:
                # The historical llm/chain/agent exact names are part of the
                # existing public behavior. Newly added fallbacks remain weak.
                cap = 0.9 if last in {"llm", "chain", "agent"} else 0.6
                return [RoleEvidence(fallback, cap)]
        return []

    def _infer_roles(self, node: ast.AST | None) -> list[RoleEvidence]:
        if node is None:
            return []
        if not isinstance(node, (ast.Call, ast.BinOp)):
            return self._roles_for_expr(node)

        evidence: dict[str, float] = {}

        def add(role: str, cap: float = 0.9) -> None:
            evidence[role] = max(evidence.get(role, 0.0), cap)

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            operands = self._roles_for_expr(node.left) + self._roles_for_expr(node.right)
            chain_caps = [
                item.confidence_cap
                for item in operands
                if item.role in {"llm_model", "llm_chain"}
            ]
            if chain_caps:
                add("llm_chain", max(chain_caps))
        elif isinstance(node, ast.Call):
            name = self._resolved_call_name(node)
            base = _basename(name)
            if base in rules.LOADER_CONSTRUCTORS:
                add("loader")
            if base in rules.MODEL_CONSTRUCTORS:
                add("llm_model")
            if base in rules.CLIENT_CONSTRUCTORS:
                add("openai_client")
            if base in rules.AGENT_FACTORIES:
                add("agent")
            if base in rules.CHAIN_FACTORIES:
                add("llm_chain")
            if base == "as_retriever":
                add("retriever")
            if base == "as_query_engine":
                add("query_engine")
            if base in {"FAISS", "Chroma", "Qdrant", "Pinecone"}:
                add("vector_store")
            for role in self._roles_for_expr(
                node.func.value if isinstance(node.func, ast.Attribute) else None
            ):
                if base in {"bind", "bind_tools", "with_config"} and role.role in {
                    "llm_model",
                    "llm_chain",
                }:
                    add(role.role, role.confidence_cap)

        return [
            RoleEvidence(role, cap)
            for role, cap in sorted(evidence.items())
        ]

    @staticmethod
    def _taint_identity(taint: Taint) -> tuple[str, str, int]:
        return (taint.kind, taint.source, taint.line)

    def _secret_usage(
        self, node: ast.AST | None
    ) -> tuple[set[tuple[str, str, int]], set[tuple[str, str, int]]]:
        """Return secret identities in privileged and ordinary prompt flows."""
        if node is None:
            return set(), set()
        key = self._canonical_key(node)
        if key is not None and (
            key in self.privileged_secrets or key in self.nonprivileged_secrets
        ):
            return (
                set(self.privileged_secrets.get(key, set())),
                set(self.nonprivileged_secrets.get(key, set())),
            )

        if isinstance(node, ast.Dict):
            role: str | None = None
            content: ast.AST | None = None
            other_values: list[ast.AST] = []
            for dict_key, value in zip(node.keys, node.values):
                key_text = _string_value(dict_key)
                if key_text == "role":
                    role = _string_value(value)
                elif key_text == "content":
                    content = value
                else:
                    other_values.append(value)
            privileged: set[tuple[str, str, int]] = set()
            nonprivileged: set[tuple[str, str, int]] = set()
            if content is not None:
                identities = {
                    self._taint_identity(taint)
                    for taint in self._eval_taints(content)
                    if taint.kind == "secret"
                }
                if role in {"system", "developer"}:
                    privileged.update(identities)
                else:
                    nonprivileged.update(identities)
            for value in other_values:
                child_privileged, child_nonprivileged = self._secret_usage(value)
                privileged.update(child_privileged)
                nonprivileged.update(child_nonprivileged)
            return privileged, nonprivileged

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            privileged: set[tuple[str, str, int]] = set()
            nonprivileged: set[tuple[str, str, int]] = set()
            for child in node.elts:
                child_privileged, child_nonprivileged = self._secret_usage(child)
                privileged.update(child_privileged)
                nonprivileged.update(child_nonprivileged)
            return privileged, nonprivileged

        if isinstance(node, ast.Call):
            if self._is_system_message_call(node):
                content = node.args[0] if node.args else None
                for keyword in node.keywords:
                    if keyword.arg == "content":
                        content = keyword.value
                identities = {
                    self._taint_identity(taint)
                    for taint in self._eval_taints(content)
                    if taint.kind == "secret"
                }
                return identities, set()
            if self._is_chat_prompt_template_call(node):
                privileged = {
                    self._taint_identity(taint)
                    for content in self._iter_privileged_tuple_contents(
                        node.args[0] if node.args else None
                    )
                    for taint in self._eval_taints(content)
                    if taint.kind == "secret"
                }
                all_identities = {
                    self._taint_identity(taint)
                    for taint in self._eval_taints(node)
                    if taint.kind == "secret"
                }
                return privileged, all_identities - privileged

        identities = {
            self._taint_identity(taint)
            for taint in self._eval_taints(node)
            if taint.kind == "secret"
        }
        return set(), identities

    def _invalidate_safe_mapping(self, key: str) -> None:
        self.constant_dicts.discard(key)
        self.safe_shell_vars.discard(key)

    def _merge_container_taints(self, key: str, taints: Iterable[Taint]) -> None:
        combined = self._unique_taints(list(self.env.get(key, [])) + list(taints))
        if combined:
            self.env[key] = combined

    def _apply_container_mutation(self, call: ast.Call) -> None:
        if not isinstance(call.func, ast.Attribute):
            return
        method = call.func.attr
        if method not in {"append", "extend", "update", "setdefault"}:
            return
        key = self._canonical_key(call.func.value)
        if key is None:
            return
        self._invalidate_safe_mapping(key)
        values = list(call.args) + [keyword.value for keyword in call.keywords]
        self._merge_container_taints(
            key,
            (
                taint
                for value in values
                for taint in self._eval_taints(value)
            ),
        )
        for value in values:
            privileged, nonprivileged = self._secret_usage(value)
            if privileged:
                self.privileged_secrets.setdefault(key, set()).update(privileged)
            if nonprivileged:
                self.nonprivileged_secrets.setdefault(key, set()).update(
                    nonprivileged
                )

    def _handle_delete_target(self, target: ast.AST) -> None:
        key = self._canonical_key(target)
        if key is None:
            return
        self.env.pop(key, None)
        self.roles.pop(key, None)
        self.privileged_secrets.pop(key, None)
        self.nonprivileged_secrets.pop(key, None)
        if isinstance(target, ast.Subscript):
            base = self._canonical_key(target.value)
            if base is not None:
                self._invalidate_safe_mapping(base)
        else:
            self._invalidate_safe_mapping(key)

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
        self._apply_container_mutation(call)
        name = self._resolved_call_name(call)
        display_name = _call_name(call)
        suffix = _basename(name)

        if name in rules.UNSAFE_DESERIALIZATION_CALLS:
            self._emit(
                "LLM03_UNSAFE_DESERIALIZATION",
                line=call.lineno,
                source=self._first_arg_text(call) or "serialized artifact",
                sink=f"{display_name}(...)",
                evidence=_safe_unparse(call),
            )
            return

        if (
            suffix == "from_pretrained" or suffix == "pipeline"
        ) and self._has_true_keyword(call, "trust_remote_code"):
            self._emit(
                "LLM03_TRUST_REMOTE_CODE_TRUE",
                line=call.lineno,
                source="remote model",
                sink=f"{display_name}(..., trust_remote_code=True)",
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
                    sink=f"{display_name}(...)",
                    evidence=_safe_unparse(call),
                    confidence=self._confidence_for_taint(
                        "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION", taint
                    ),
                )
            return

        if name in rules.SHELL_EXEC_CALLS:
            if (
                name != "asyncio.create_subprocess_exec"
                and call.args
                and self._is_safe_shell_command_expr(call.args[0])
            ):
                return
            taint = self._first_taint(list(call.args) + [kw.value for kw in call.keywords], {"llm_output"})
            if taint is not None:
                self._emit(
                    "LLM05_LLM_OUTPUT_TO_SHELL",
                    line=call.lineno,
                    source=taint.source,
                    sink=f"{display_name}(...)",
                    evidence=_safe_unparse(call),
                    confidence=self._confidence_for_taint(
                        "LLM05_LLM_OUTPUT_TO_SHELL", taint
                    ),
                )
            return

        if self._is_sql_execute_call(call):
            query_taint = self._first_taint(call.args[:1], {"llm_output"})
            if query_taint is not None:
                self._emit(
                    "LLM05_LLM_OUTPUT_TO_SQL",
                    line=call.lineno,
                    source=query_taint.source,
                    sink=f"{display_name}(...)",
                    evidence=_safe_unparse(call),
                    confidence=self._confidence_for_taint(
                        "LLM05_LLM_OUTPUT_TO_SQL", query_taint
                    ),
                )
            return

        if self._is_system_message_call(call):
            self._inspect_system_message_call(call)

        if self._is_chat_prompt_template_call(call):
            self._inspect_chat_prompt_template_call(call)

        self._inspect_privileged_keyword_call(call)

        if self._is_llm_input_call(call):
            self._inspect_llm_input_call(call)

    def _inspect_llm_input_call(self, call: ast.Call) -> None:
        candidates: list[ast.AST] = list(call.args)
        call_cap = self._llm_call_confidence_cap(call)
        for keyword in call.keywords:
            if keyword.arg in rules.LLM_INPUT_KEYWORDS:
                candidates.append(keyword.value)

        for candidate in candidates:
            self._inspect_system_prompt_expr(candidate)
            privileged, nonprivileged = self._secret_usage(candidate)
            for taint in self._eval_taints(candidate):
                if taint.kind == "external_content":
                    self._emit(
                        "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                        line=call.lineno,
                        source=taint.source,
                        sink=f"{_call_name(call)}(...)",
                        evidence=_safe_unparse(call),
                        confidence=min(
                            self._confidence_for_taint(
                                "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT", taint
                            ),
                            call_cap,
                        ),
                    )
                elif taint.kind == "secret":
                    identity = self._taint_identity(taint)
                    if identity in privileged and identity not in nonprivileged:
                        continue
                    self._emit(
                        "LLM02_SECRET_TO_LLM_INPUT",
                        line=call.lineno,
                        source=taint.source,
                        sink=f"{_call_name(call)}(...)",
                        evidence=_safe_unparse(call),
                        confidence=min(
                            self._confidence_for_taint(
                                "LLM02_SECRET_TO_LLM_INPUT", taint
                            ),
                            call_cap,
                        ),
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

        if role not in {"system", "developer"} or content is None:
            return False

        for taint in self._eval_taints(content):
            if taint.kind == "secret":
                self._emit(
                    "LLM07_SECRET_IN_SYSTEM_PROMPT",
                    line=node.lineno,
                    source=taint.source,
                    sink=f'{{"role": "{role}", "content": ...}}',
                    evidence=_safe_unparse(node),
                    confidence=self._confidence_for_taint(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT", taint
                    ),
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
                    confidence=self._confidence_for_taint(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT", taint
                    ),
                )
                emitted = True
        return emitted

    def _inspect_chat_prompt_template_call(self, call: ast.Call) -> bool:
        messages = call.args[0] if call.args else None
        emitted = False
        for content in self._iter_privileged_tuple_contents(messages):
            for taint in self._eval_taints(content):
                if taint.kind == "secret":
                    self._emit(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT",
                        line=getattr(content, "lineno", call.lineno),
                        source=taint.source,
                        sink='ChatPromptTemplate.from_messages(("system", ...))',
                        evidence=_safe_unparse(call),
                        confidence=self._confidence_for_taint(
                            "LLM07_SECRET_IN_SYSTEM_PROMPT", taint
                        ),
                    )
                    emitted = True
        return emitted

    def _inspect_privileged_keyword_call(self, call: ast.Call) -> bool:
        emitted = False
        name = self._resolved_call_name(call)
        is_responses_call = _endswith_segments(
            name, ("client", "responses", "create")
        )
        is_agent_factory = _basename(name) in (
            rules.AGENT_FACTORIES | rules.AGENT_BINDING_CALLS
        )
        for keyword in call.keywords:
            if keyword.arg not in rules.PRIVILEGED_PROMPT_KEYWORDS:
                continue
            if keyword.arg == "instructions" and not is_responses_call:
                continue
            if keyword.arg == "system_prompt" and not is_agent_factory:
                continue
            for taint in self._eval_taints(keyword.value):
                if taint.kind != "secret":
                    continue
                self._emit(
                    "LLM07_SECRET_IN_SYSTEM_PROMPT",
                    line=call.lineno,
                    source=taint.source,
                    sink=f"{_call_name(call)}({keyword.arg}=...)",
                    evidence=_safe_unparse(call),
                    confidence=self._confidence_for_taint(
                        "LLM07_SECRET_IN_SYSTEM_PROMPT", taint
                    ),
                )
                emitted = True
        return emitted

    # Taint evaluation -----------------------------------------------------
    def _eval_taints(self, node: ast.AST | None) -> list[Taint]:
        if node is None or self._is_masked_expr(node):
            return []

        key = self._canonical_key(node)
        if key is not None and key in self.env:
            return list(self.env[key])

        source = self._classify_source(node)
        if source is not None:
            return [source]

        if isinstance(node, ast.Name):
            if self._looks_secret_name(node.id):
                return [Taint("secret", node.id, getattr(node, "lineno", 0), 0.6)]
            if any(hint in node.id.lower() for hint in rules.EXTERNAL_NAME_HINTS):
                return [
                    Taint("external_content", node.id, getattr(node, "lineno", 0), 0.6)
                ]
            return []

        if isinstance(node, ast.Attribute):
            inherited = self._eval_taints(node.value)
            return inherited

        if isinstance(node, ast.Subscript):
            if self._is_safe_shell_mapping_lookup(node):
                return []
            return self._unique_taints(self._eval_taints(node.value) + self._eval_taints(node.slice))

        if isinstance(node, ast.Await):
            return self._eval_taints(node.value)

        if isinstance(node, ast.NamedExpr):
            taints = self._eval_taints(node.value)
            self._handle_assign([node.target], node.value, getattr(node, "lineno", 0))
            return taints

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

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._eval_comprehension(node, [node.elt])

        if isinstance(node, ast.DictComp):
            return self._eval_comprehension(node, [node.key, node.value])

        if isinstance(node, ast.Call):
            if self._is_string_format_call(node):
                return self._taints_from_call_inputs(node, include_receiver=True)
            # Unknown transformations are not sanitizers. Shallow analysis
            # conservatively propagates argument/receiver taint to the result.
            return self._taints_from_call_inputs(node, include_receiver=True)

        return []

    def _classify_source(self, node: ast.AST) -> Taint | None:
        if isinstance(node, ast.Call):
            name = self._resolved_call_name(node)
            suffix = _basename(name)
            root = _root_name(name)

            if self._is_secret_env_call(node):
                return Taint("secret", _safe_unparse(node), node.lineno)

            if name in rules.REQUESTS_CONTENT_METHODS:
                return Taint("external_content", _safe_unparse(node), node.lineno)

            if suffix == "read":
                base = getattr(node.func, "value", None)
                if self._is_open_call(base):
                    return Taint("external_content", _safe_unparse(node), node.lineno)
                inherited = self._first_taint([base] if base is not None else [], {"external_content"})
                if inherited is not None:
                    return Taint(
                        "external_content",
                        _safe_unparse(node),
                        node.lineno,
                        inherited.confidence_cap,
                    )

            if suffix == "read_text":
                return Taint("external_content", _safe_unparse(node), node.lineno)

            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            receiver_roles = self._roles_for_expr(receiver)
            role_names = {role.role for role in receiver_roles}
            role_cap = max(
                (role.confidence_cap for role in receiver_roles), default=0.9
            )

            if suffix in rules.LOADER_METHODS and "loader" in role_names:
                return Taint(
                    "external_content", _safe_unparse(node), node.lineno, role_cap
                )

            if suffix in rules.RETRIEVER_METHODS and "retriever" in role_names:
                return Taint(
                    "external_content", _safe_unparse(node), node.lineno, role_cap
                )

            if suffix in rules.VECTOR_STORE_METHODS and (
                "vector_store" in role_names or "retriever" in role_names
            ):
                return Taint(
                    "external_content", _safe_unparse(node), node.lineno, role_cap
                )

            if suffix in rules.QUERY_ENGINE_METHODS and "query_engine" in role_names:
                return Taint("llm_output", _safe_unparse(node), node.lineno, role_cap)

            if suffix == "get_content":
                inherited = self._first_taint(
                    [receiver] if receiver is not None else [],
                    {"external_content"},
                )
                if inherited is not None:
                    return Taint(
                        "external_content",
                        _safe_unparse(node),
                        node.lineno,
                        inherited.confidence_cap,
                    )

            if suffix == "load" and name not in rules.UNSAFE_DESERIALIZATION_CALLS:
                if root.lower().endswith("loader") or root in rules.EXTERNAL_LOADERS or root == "loader":
                    return Taint("external_content", _safe_unparse(node), node.lineno)

            if suffix in rules.EXTERNAL_RETRIEVAL_SUFFIXES:
                receiver_name = self._receiver_last_segment(node)
                if receiver_name in {"retriever", "vector_store"}:
                    return Taint("external_content", _safe_unparse(node), node.lineno, 0.6)

            if self._is_llm_output_call(node):
                return Taint(
                    "llm_output",
                    _safe_unparse(node),
                    node.lineno,
                    self._llm_call_confidence_cap(node),
                )

        if isinstance(node, ast.Attribute):
            if self._is_secret_environ_subscript(getattr(node, "value", None)):
                return Taint("secret", _safe_unparse(node), node.lineno)

            if node.attr in {"text", "content", "page_content"}:
                base = node.value
                if (
                    isinstance(base, ast.Call)
                    and self._resolved_call_name(base) in rules.REQUESTS_CONTENT_METHODS
                ):
                    return Taint("external_content", _safe_unparse(node), node.lineno)
                inherited = self._first_taint([base], {"external_content"})
                if inherited is not None:
                    return Taint(
                        "external_content",
                        _safe_unparse(node),
                        node.lineno,
                        inherited.confidence_cap,
                    )

            inherited = self._first_taint([node.value], {"llm_output"})
            if inherited is not None:
                return Taint(
                    "llm_output",
                    _safe_unparse(node),
                    node.lineno,
                    inherited.confidence_cap,
                )

        if isinstance(node, ast.Subscript) and self._is_secret_environ_subscript(node):
            return Taint("secret", _safe_unparse(node), node.lineno)

        return None

    # Classification helpers ---------------------------------------------
    def _is_llm_output_call(self, call: ast.Call) -> bool:
        return self._is_known_llm_call(call)

    def _is_llm_input_call(self, call: ast.Call) -> bool:
        return self._is_known_llm_call(call)

    def _is_known_llm_call(self, call: ast.Call) -> bool:
        """Use identical, receiver-aware criteria for LLM inputs and outputs."""
        name = self._resolved_call_name(call)
        if any(
            _endswith_segments(name, ending)
            for ending in rules.OPENAI_SDK_CALL_SEGMENTS
        ):
            return True

        if not isinstance(call.func, ast.Attribute):
            return False
        method = call.func.attr
        receiver = call.func.value
        receiver_key = self._canonical_key(receiver)
        receiver_last = (
            receiver_key.rsplit(".", 1)[-1]
            if receiver_key
            else self._receiver_last_segment(call)
        )

        # Preserve the exact historical receiver/method contract without
        # turning every object with invoke/run into an LLM.
        if (receiver_last, method) in rules.KNOWN_LLM_RECEIVER_METHODS:
            return True

        roles = {item.role for item in self._roles_for_expr(receiver)}
        if roles.intersection({"llm_model", "llm_chain"}):
            return method in rules.MODEL_CALL_METHODS
        if "agent" in roles:
            return method in rules.AGENT_CALL_METHODS
        return False

    def _llm_call_confidence_cap(self, call: ast.Call) -> float:
        name = self._resolved_call_name(call)
        if any(
            _endswith_segments(name, ending)
            for ending in rules.OPENAI_SDK_CALL_SEGMENTS
        ):
            return 0.9
        if not isinstance(call.func, ast.Attribute):
            return 0.9
        receiver = call.func.value
        receiver_key = self._canonical_key(receiver)
        receiver_last = (
            receiver_key.rsplit(".", 1)[-1]
            if receiver_key
            else self._receiver_last_segment(call)
        )
        if (receiver_last, call.func.attr) in rules.KNOWN_LLM_RECEIVER_METHODS:
            return 0.9
        caps = [
            role.confidence_cap
            for role in self._roles_for_expr(receiver)
            if role.role in {"llm_model", "llm_chain", "agent"}
        ]
        return max(caps, default=0.6)

    def _is_sql_execute_call(self, call: ast.Call) -> bool:
        name = self._resolved_call_name(call)
        if _basename(name) not in rules.SQL_EXEC_SUFFIXES:
            return False
        if not isinstance(call.func, ast.Attribute):
            return False
        receiver = call.func.value
        if self._receiver_last_segment(call) in rules.SQL_EXEC_ROOTS:
            return True
        return any(
            role.role == "sql_connection"
            for role in self._roles_for_expr(receiver)
        )

    def _is_system_message_call(self, call: ast.Call) -> bool:
        return _basename(self._resolved_call_name(call)) == "SystemMessage"

    def _is_chat_prompt_template_call(self, call: ast.Call) -> bool:
        return _endswith_segments(
            self._resolved_call_name(call),
            ("ChatPromptTemplate", "from_messages"),
        )

    def _iter_privileged_tuple_contents(
        self, node: ast.AST | None
    ) -> Iterable[ast.AST]:
        if not isinstance(node, (ast.List, ast.Tuple)):
            return []
        contents: list[ast.AST] = []
        for elt in node.elts:
            if not isinstance(elt, (ast.Tuple, ast.List)) or len(elt.elts) < 2:
                continue
            if _string_value(elt.elts[0]) in {"system", "developer"}:
                contents.append(elt.elts[1])
        return contents

    def _is_secret_env_call(self, call: ast.Call) -> bool:
        name = self._resolved_call_name(call)
        if name not in {"os.getenv", "os.environ.get"}:
            return False
        key = _string_value(call.args[0]) if call.args else None
        return bool(key and self._looks_secret_env_key(key))

    def _is_secret_environ_subscript(self, node: ast.AST | None) -> bool:
        if not isinstance(node, ast.Subscript):
            return False
        if self._resolved_attr_chain(node.value) != "os.environ":
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
        return self._is_masking_literal(node)

    def _is_masking_literal(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            return False
        text = node.value.strip()
        if text.upper() in rules.MASKING_LITERALS:
            return True
        return len(text) >= 3 and set(text) <= {"*", "x", "X"}

    def _is_string_format_call(self, call: ast.Call) -> bool:
        return _basename(_call_name(call)) == "format"

    def _is_open_call(self, node: ast.AST | None) -> bool:
        return isinstance(node, ast.Call) and self._resolved_call_name(node) == "open"

    def _has_taint(self, node: ast.AST | None, kinds: set[str]) -> bool:
        return any(taint.kind in kinds for taint in self._eval_taints(node))

    def _first_taint(self, nodes: Iterable[ast.AST], kinds: set[str]) -> Taint | None:
        for node in nodes:
            for taint in self._eval_taints(node):
                if taint.kind in kinds:
                    return taint
        return None

    def _eval_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        outputs: list[ast.AST],
    ) -> list[Taint]:
        saved_env = dict(self.env)
        saved_roles = {key: dict(value) for key, value in self.roles.items()}
        saved_privileged = {key: set(value) for key, value in self.privileged_secrets.items()}
        saved_nonprivileged = {
            key: set(value) for key, value in self.nonprivileged_secrets.items()
        }
        try:
            for generator in node.generators:
                iter_taints = self._eval_taints(generator.iter)
                self._bind_target(
                    generator.target,
                    iter_taints,
                    self._roles_for_expr(generator.iter),
                    *self._secret_usage(generator.iter),
                    lineno=getattr(generator.target, "lineno", node.lineno),
                )
                for condition in generator.ifs:
                    self._eval_taints(condition)
            return self._unique_taints(
                taint for output in outputs for taint in self._eval_taints(output)
            )
        finally:
            self.env = saved_env
            self.roles = saved_roles
            self.privileged_secrets = saved_privileged
            self.nonprivileged_secrets = saved_nonprivileged

    def _taints_from_call_inputs(
        self, call: ast.Call, *, include_receiver: bool
    ) -> list[Taint]:
        inputs: list[ast.AST] = []
        if include_receiver and isinstance(call.func, ast.Attribute):
            inputs.append(call.func.value)
        inputs.extend(call.args)
        inputs.extend(keyword.value for keyword in call.keywords)
        return self._unique_taints(
            taint for item in inputs for taint in self._eval_taints(item)
        )

    @staticmethod
    def _confidence_for_taint(rule_id: str, taint: Taint) -> float:
        return min(rules.DEFAULT_CONFIDENCE[rule_id], taint.confidence_cap)

    def _first_arg_text(self, call: ast.Call) -> str | None:
        return _safe_unparse(call.args[0]) if call.args else None

    @staticmethod
    def _has_true_keyword(call: ast.Call, name: str) -> bool:
        return any(keyword.arg == name and _bool_true(keyword.value) for keyword in call.keywords)

    @staticmethod
    def _unique_taints(taints: Iterable[Taint]) -> list[Taint]:
        positions: dict[tuple[str, str, int], int] = {}
        unique: list[Taint] = []
        for taint in taints:
            key = (taint.kind, taint.source, taint.line)
            position = positions.get(key)
            if position is None:
                positions[key] = len(unique)
                unique.append(taint)
            elif taint.confidence_cap > unique[position].confidence_cap:
                unique[position] = taint
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
        if not isinstance(node, ast.Subscript):
            return False
        key = self._canonical_key(node.value)
        return key is not None and key in self.constant_dicts

    def _is_safe_shell_command_expr(self, node: ast.AST) -> bool:
        key = self._canonical_key(node)
        if key is not None and key in self.safe_shell_vars:
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

            for child in self._walk_function_scope(node):
                if not isinstance(child, ast.Call):
                    continue
                name = self._resolved_call_name(child)
                if self._call_is_destructive_or_execution(name):
                    destructive.append(name)
                if self._call_is_external_side_effect(child):
                    side_effects.append(name)

            self.function_caps[node.name] = FunctionCapability(
                destructive_or_execution=self._unique_strings(destructive),
                external_side_effect=self._unique_strings(side_effects),
                line=node.lineno,
            )

    @staticmethod
    def _walk_function_scope(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Iterable[ast.AST]:
        """Walk one function body without attributing nested scopes to it."""
        stack: list[ast.AST] = list(reversed(node.body))
        while stack:
            current = stack.pop()
            yield current
            if isinstance(
                current,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            ):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(current))))

    def _collect_tool_bindings(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._collect_tool_assignment(node)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_agent_binding_call(node):
                for func_name in sorted(self._extract_bound_tool_functions(node)):
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
            name = self._resolved_call_name(node)
            basename = _basename(name)
            is_factory = any(
                _endswith_segments(name, tuple(suffix.split(".")))
                for suffix in rules.TOOL_FACTORY_SUFFIXES
            )
            if is_factory or basename in rules.TOOL_CONSTRUCTOR_NAMES:
                func = self._extract_tool_function_name(node)
                return {func} if func else set()

        return set()

    def _extract_tool_function_name(self, call: ast.Call) -> str | None:
        for keyword in call.keywords:
            if keyword.arg in {"func", "fn", "coroutine"} and isinstance(keyword.value, ast.Name):
                return keyword.value.id
        for arg in call.args:
            if isinstance(arg, ast.Name):
                return arg.id
        return None

    def _is_agent_binding_call(self, call: ast.Call) -> bool:
        name = self._resolved_call_name(call)
        basename = _basename(name)
        if basename in rules.AGENT_BINDING_CALLS:
            return True
        if _endswith_segments(name, ("AgentExecutor", "from_agent_and_tools")):
            return True
        parts = name.split(".")
        return len(parts) >= 2 and parts[-1] == "from_tools" and parts[-2].endswith("Agent")

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
        name = self._resolved_call_name(call)
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
        if (
            isinstance(first, ast.Call)
            and _basename(self._resolved_call_name(first)) == "text"
            and first.args
        ):
            first = first.args[0]
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
        seen: set[str] = set()
        ordered = sorted(
            findings,
            key=lambda finding: (
                finding.file,
                finding.rule_id,
                finding.line,
                finding.sink,
                -finding.confidence,
                finding.source,
                finding.finding_id,
            ),
        )
        for finding in ordered:
            if finding.finding_id in seen:
                continue
            seen.add(finding.finding_id)
            deduped.append(finding)

        llm07_findings = [
            finding for finding in deduped
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
            finding for finding in deduped
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
