#!/usr/bin/env python3
"""Read-only verifier for AxiomLayer's pinned Homebrew formula input.

The verifier intentionally does not load Homebrew, execute formula Ruby, install
packages, fetch bottles, or follow formula/cask artifact URLs. It treats the tap
as source data and fails closed when its immutable anchors or declarations drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "axiomlayer-homebrew-tap-integrity-v1"
EXPECTED_ACTIVE_WORKFLOW_SHA256 = (
    "8e265bed2abfb77c738411ec43081600c63199c47e3630cbb9a04b34d5593f36"
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REVISION_PIN = re.compile(r'\brevision:\s*["\']([0-9a-f]{40}|[0-9a-f]{64})["\']')
SOURCE_URL = re.compile(r'^\s*url\s+\(?["\']https?://', re.MULTILINE)
PINNED_POLICY_CONDITION = (
    "github.server_url == 'https://github.com' && "
    "github.repository == 'axiomlayer/homebrew-core' && "
    "github.event.repository.full_name == 'axiomlayer/homebrew-core' && "
    "github.event.repository.default_branch == 'main' && "
    "((github.event_name == 'pull_request' && github.base_ref == 'main' && "
    "github.event.pull_request.head.repo.full_name == 'axiomlayer/homebrew-core' && "
    "github.ref == format('refs/pull/{0}/merge', "
    "github.event.pull_request.number) && github.workflow_ref == "
    "format('axiomlayer/homebrew-core/.github/workflows/"
    "axiomlayer-tap-integrity.yml@refs/pull/{0}/merge', "
    "github.event.pull_request.number)) || "
    "((github.event_name == 'push' || github.event_name == 'schedule' || "
    "github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main' && "
    "github.ref_protected == true && github.workflow_ref == "
    "'axiomlayer/homebrew-core/.github/workflows/"
    "axiomlayer-tap-integrity.yml@refs/heads/main'))"
)
CANARY_CONDITION = (
    "github.server_url == 'https://github.com' && "
    "github.repository == 'axiomlayer/homebrew-core' && "
    "github.event.repository.full_name == 'axiomlayer/homebrew-core' && "
    "github.event.repository.default_branch == 'main' && "
    "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && "
    "github.ref == 'refs/heads/main' && github.ref_protected == true && "
    "github.workflow_ref == 'axiomlayer/homebrew-core/.github/workflows/"
    "axiomlayer-tap-integrity.yml@refs/heads/main'"
)
EXPECTED_JOB_RUNNERS = ["ubuntu-24.04", "${{ matrix.runner }}", "ubuntu-24.04"]
EXPECTED_MATRIX_RUNNERS = [
    "ubuntu-24.04",
    "ubuntu-24.04-arm",
    "macos-15-intel",
    "macos-15",
]
STRICT_YAML_RUBY = r"""
require "psych"

def reject_ambiguous_mapping(node, path = [])
  if node.respond_to?(:anchor) && node.anchor
    warn "YAML anchors are forbidden at #{path.join('.')}"
    exit 1
  end
  case node
  when Psych::Nodes::Alias
    warn "YAML aliases are forbidden at #{path.join('.')}"
    exit 1
  when Psych::Nodes::Mapping
    seen = {}
    node.children.each_slice(2) do |key, value|
      unless key.is_a?(Psych::Nodes::Scalar) && key.anchor.nil? && key.tag.nil?
        warn "non-scalar or tagged YAML key is forbidden at #{path.join('.')}"
        exit 1
      end
      name = key.value
      if name == "<<" || seen.key?(name)
        warn "duplicate or merged YAML key #{name.inspect} at #{path.join('.')}"
        exit 1
      end
      seen[name] = true
      reject_ambiguous_mapping(value, path + [name])
    end
  when Psych::Nodes::Sequence
    node.children.each_with_index do |child, index|
      reject_ambiguous_mapping(child, path + [index.to_s])
    end
  end
end

begin
  stream = Psych.parse_stream(STDIN.read, filename: "workflow.yml")
rescue Psych::SyntaxError => error
  warn error.message
  exit 1
end
unless stream.children.length == 1 && stream.children.first.root
  warn "workflow must contain exactly one YAML document"
  exit 1
end
reject_ambiguous_mapping(stream.children.first.root)
"""
RUBY_DSL_CALLS = r"""
require "json"
require "ripper"

def strip_method_bodies(source)
  lines = source.lines
  tokens = Ripper.lex(source)
  ranges = []
  tokens.each_with_index do |token, index|
    position, event, value = token[0], token[1], token[2]
    next unless event == :on_kw && value == "def"
    start_line, column = position
    depth = 0
    endless = false
    tokens[(index + 1)..-1].each do |later|
      break if later[0][0] != start_line
      case later[2]
      when "(", "[", "{"
        depth += 1
      when ")", "]", "}"
        depth -= 1 if depth > 0
      when "="
        endless = true if depth == 0 && later[1] == :on_op
      end
    end
    if endless
      ranges << [start_line, start_line]
      next
    end
    closing = tokens[(index + 1)..-1].find do |later|
      later[1] == :on_kw && later[2] == "end" && later[0][1] == column
    end
    unless closing
      warn "Ruby method body is not formatter-aligned"
      exit 1
    end
    ranges << [start_line, closing[0][0]]
  end
  ranges.reverse_each do |first, last|
    (first..last).each do |line_number|
      original = lines[line_number - 1]
      lines[line_number - 1] = original&.end_with?("\n") ? "\n" : ""
    end
  end
  lines.join
end

def static_string(node)
  return nil unless node.is_a?(Array)
  case node[0]
  when :string_literal
    content = node[1]
    return nil unless content.is_a?(Array) && content[0] == :string_content
    parts = content[1..-1]
    return "" if parts.empty?
    return nil unless parts.all? do |part|
      part.is_a?(Array) && part[0] == :@tstring_content &&
        !$heredoc_string_positions.key?(part[2])
    end
    parts.map { |part| part[1] }.join
  when :string_concat
    left = static_string(node[1])
    right = static_string(node[2])
    left && right ? left + right : nil
  end
end

def string_prefix(node)
  return nil unless node.is_a?(Array) && node[0] == :string_literal
  content = node[1]
  return nil unless content.is_a?(Array) && content[0] == :string_content
  prefix = []
  content[1..-1].each do |part|
    break unless part.is_a?(Array) && part[0] == :@tstring_content
    prefix << part[1]
  end
  prefix.join
end

def static_symbol(node)
  return nil unless node.is_a?(Array) && node[0] == :symbol_literal
  symbol = node[1]
  return nil unless symbol.is_a?(Array) && symbol[0] == :symbol
  token = symbol[1]
  return nil unless token.is_a?(Array) && token[0].to_s.start_with?("@")
  token[1]
end

def association_key(node)
  return nil unless node.is_a?(Array)
  return node[1].sub(/:\z/, "") if node[0] == :@label
  static_symbol(node) || static_string(node)
end

def argument_nodes(node)
  return [] if node.nil?
  return nil unless node.is_a?(Array)
  return node if !node.empty? && node.all? do |argument|
    argument.is_a?(Array) && argument[0].is_a?(Symbol)
  end
  case node[0]
  when :arg_paren
    argument_nodes(node[1])
  when :args_add_block
    return nil unless node[2] == false
    arguments = node[1]
    return [] if arguments == []
    return arguments if arguments.is_a?(Array) &&
      arguments.all? { |argument| argument.is_a?(Array) }
  when :args_new
    []
  end
end

def map_entries(node)
  return nil unless node.is_a?(Array)
  associations = case node[0]
                 when :bare_assoc_hash
                   node[1]
                 when :hash
                   list = node[1]
                   list[1] if list.is_a?(Array) && list[0] == :assoclist_from_args
                 end
  return nil unless associations.is_a?(Array) && !associations.empty?
  return nil unless associations.all? do |association|
    association.is_a?(Array) && association[0] == :assoc_new
  end
  associations.map do |association|
    key_node = association[1]
    key_kind, key = if key_node.is_a?(Array) && key_node[0] == :@label
                      ["label", key_node[1].sub(/:\z/, "")]
                    elsif (value = static_symbol(key_node))
                      ["symbol", value]
                    elsif (value = static_string(key_node))
                      ["string", value]
                    else
                      ["dynamic", nil]
                    end
    value_node = association[2]
    value_kind, value = if (literal = static_string(value_node))
                          ["literal", literal]
                        elsif (symbol = static_symbol(value_node))
                          ["symbol", symbol]
                        else
                          ["dynamic", nil]
                        end
    {
      "keyKind" => key_kind,
      "key" => key,
      "valueKind" => value_kind,
      "value" => value,
    }
  end
end

def argument_descriptor(node)
  arguments = argument_nodes(node)
  return {"kind" => "dynamic", "value" => nil, "entries" => []} if arguments.nil?
  return {"kind" => "none", "value" => nil, "entries" => []} if arguments.empty?
  if arguments.length > 1
    literal = static_string(arguments.first)
    option_entries = arguments[1..-1].flat_map do |argument|
      entries = map_entries(argument)
      break nil unless entries
      entries
    end
    if literal && option_entries
      return {"kind" => "literalWithOptions", "value" => literal, "entries" => option_entries}
    end
    return {"kind" => "dynamic", "value" => nil, "entries" => []}
  end
  argument = arguments.first
  if (literal = static_string(argument))
    return {"kind" => "literal", "value" => literal, "entries" => []}
  end
  if (symbol = static_symbol(argument))
    return {"kind" => "symbol", "value" => symbol, "entries" => []}
  end
  if argument.is_a?(Array) && argument[0] == :var_ref &&
     argument[1].is_a?(Array) && argument[1][0] == :@const
    return {"kind" => "constant", "value" => argument[1][1], "entries" => []}
  end
  entries = map_entries(argument)
  return {"kind" => "map", "value" => nil, "entries" => entries} if entries
  {"kind" => "dynamic", "value" => nil, "entries" => []}
end

def collect_literals(node, strings, symbols, named, prefixes)
  return unless node.is_a?(Array)
  prefix = string_prefix(node)
  prefixes << prefix unless prefix.nil?
  string = static_string(node)
  unless string.nil?
    strings << string
    return
  end
  symbol = static_symbol(node)
  unless symbol.nil?
    symbols << symbol
    return
  end
  if node[0] == :assoc_new
    key = association_key(node[1])
    value_strings = []
    value_symbols = []
    value_prefixes = []
    collect_literals(node[2], value_strings, value_symbols, {}, value_prefixes)
    named[key] = {"strings" => value_strings, "symbols" => value_symbols} if key
    strings.concat(value_strings)
    symbols.concat(value_symbols)
    prefixes.concat(value_prefixes)
    return
  end
  containers = [
    :arg_paren,
    :args_add,
    :args_add_block,
    :args_new,
    :assoclist_from_args,
    :bare_assoc_hash,
    :hash,
  ]
  if !node[0].is_a?(Symbol) || containers.include?(node[0])
    node.each { |child| collect_literals(child, strings, symbols, named, prefixes) }
  end
end

def call_parts(node)
  return nil unless node.is_a?(Array)
  case node[0]
  when :command
    token = node[1]
    args = node[2]
  when :method_add_arg
    target = node[1]
    return nil unless target.is_a?(Array) && [:fcall, :vcall].include?(target[0])
    token = target[1]
    args = node[2]
  when :fcall, :vcall
    token = node[1]
    args = nil
  else
    return nil
  end
  return nil unless token.is_a?(Array) && token[0] == :@ident
  {"name" => token[1], "line" => token[2][0], "args" => args}
end

def append_call(calls, parts, scope, has_block)
  strings = []
  symbols = []
  named = {}
  prefixes = []
  collect_literals(parts["args"], strings, symbols, named, prefixes)
  calls << {
    "name" => parts["name"],
    "line" => parts["line"],
    "scope" => scope,
    "block" => has_block,
    "strings" => strings,
    "stringPrefixes" => prefixes,
    "symbols" => symbols,
    "named" => named,
    "argument" => argument_descriptor(parts["args"]),
  }
end

def walk(node, scope, calls, serial)
  return unless node.is_a?(Array)
  if node[0] == :method_add_block
    parts = call_parts(node[1])
    if parts
      append_call(calls, parts, scope, true)
      serial[0] += 1
      block_scope = scope + ["#{parts['name']}@#{parts['line']}:#{serial[0]}"]
      walk(node[2], block_scope, calls, serial)
      return
    end
  end
  parts = call_parts(node)
  if parts
    append_call(calls, parts, scope, false)
    walk(parts["args"], scope, calls, serial)
    return
  end
  node.each { |child| walk(child, scope, calls, serial) }
end

source = STDIN.read
$heredoc_string_positions = {}
heredoc_depth = 0
Ripper.lex(source).each do |token|
  position, event = token[0], token[1]
  heredoc_depth += 1 if event == :on_heredoc_beg
  $heredoc_string_positions[position] = true if
    event == :on_tstring_content && heredoc_depth > 0
  heredoc_depth -= 1 if event == :on_heredoc_end && heredoc_depth > 0
end
tree = Ripper.sexp(strip_method_bodies(source))
unless tree
  warn "Ruby source did not parse"
  exit 1
end
calls = []
walk(tree, [], calls, [0])
STDOUT.write(JSON.generate(calls))
"""


class IntegrityViolation(RuntimeError):
    """A fail-closed policy violation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityViolation(message)


def parse_json_object(text: str, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label} contains a duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
        )
    except json.JSONDecodeError as error:
        raise IntegrityViolation(f"cannot parse {label}: {error}") from error
    require(isinstance(value, dict), f"{label} root must be an object")
    return value


def read_json(path: Path) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink(),
        f"policy must be a regular non-symlink file: {path}",
    )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise IntegrityViolation(f"cannot read policy {path}: {error}") from error
    return parse_json_object(text, f"policy {path}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_id(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - Git object identity


def isolated_git_environment(home: Path) -> dict[str, str]:
    """Return a non-interactive Git environment with no inherited Git policy."""

    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_") or name in {
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
        }:
            environment.pop(name, None)
    environment.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
        }
    )
    return environment


def git(
    repo: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="axiomlayer-git-home-") as temporary:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_git_environment(Path(temporary)),
        )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise IntegrityViolation(
            f"git {' '.join(arguments)} failed in {repo}: {detail}"
        )
    return result


def git_output(repo: Path, *arguments: str) -> str:
    return git(repo, *arguments).stdout.strip()


def git_bytes(repo: Path, *arguments: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="axiomlayer-git-home-") as temporary:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=isolated_git_environment(Path(temporary)),
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise IntegrityViolation(
            f"git {' '.join(arguments)} failed in {repo}: {detail}"
        )
    return result.stdout


def git_tree_entry(repo: Path, revision: str, path: str) -> tuple[str, str, str]:
    lines = git_output(repo, "ls-tree", revision, "--", path).splitlines()
    require(len(lines) == 1, f"expected one committed tree entry for {path}")
    try:
        metadata, actual_path = lines[0].split("\t", 1)
        mode, object_type, object_id = metadata.split()
    except ValueError as error:
        raise IntegrityViolation(
            f"malformed committed tree entry for {path}"
        ) from error
    require(actual_path == path, f"committed tree path drifted for {path}")
    require(HEX40.fullmatch(object_id) is not None, f"invalid Git object for {path}")
    return mode, object_type, object_id


def git_index_entry(repo: Path, path: str) -> tuple[str, str]:
    lines = git_output(repo, "ls-files", "--stage", "--", path).splitlines()
    require(len(lines) == 1, f"expected one staged index entry for {path}")
    try:
        metadata, actual_path = lines[0].split("\t", 1)
        mode, object_id, stage = metadata.split()
    except ValueError as error:
        raise IntegrityViolation(f"malformed staged index entry for {path}") from error
    require(
        actual_path == path and stage == "0", f"staged index path drifted for {path}"
    )
    require(HEX40.fullmatch(object_id) is not None, f"invalid staged object for {path}")
    return mode, object_id


def isolated_ruby_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "RUBYLIB": "",
        "RUBYOPT": "",
        "TMPDIR": str(home),
    }


def ruby_executable() -> str:
    executable = shutil.which("ruby")
    require(executable is not None, "Ruby is required for non-evaluating syntax checks")
    return executable


def verify_unambiguous_yaml(text: str, label: str) -> None:
    with tempfile.TemporaryDirectory(prefix="axiomlayer-yaml-") as temporary:
        result = subprocess.run(
            [ruby_executable(), "--disable-gems", "-rpsych", "-e", STRICT_YAML_RUBY],
            check=False,
            input=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_ruby_environment(Path(temporary)),
        )
    require(
        result.returncode == 0,
        f"{label} is malformed or ambiguous YAML: {result.stderr.strip()}",
    )


def validate_hex(value: Any, bits: int, label: str) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    pattern = HEX40 if bits == 160 else HEX64
    require(
        pattern.fullmatch(value) is not None, f"{label} must be lowercase hex-{bits}"
    )
    return value


def sorted_unique_strings(value: Any, label: str) -> list[str]:
    require(
        isinstance(value, list) and all(isinstance(item, str) for item in value),
        f"{label} must be a string list",
    )
    require(value == sorted(set(value)), f"{label} must be sorted and unique")
    return value


def ordered_unique_strings(value: Any, label: str) -> list[str]:
    require(
        isinstance(value, list) and all(isinstance(item, str) for item in value),
        f"{label} must be a string list",
    )
    require(len(value) == len(set(value)), f"{label} must be unique")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == expected,
        f"{label} fields drifted: missing={sorted(expected - actual)}, "
        f"unexpected={sorted(actual - expected)}",
    )


def validate_policy(
    policy: dict[str, Any],
    *,
    expected_active_workflow_sha256: str | None = EXPECTED_ACTIVE_WORKFLOW_SHA256,
) -> None:
    require_exact_keys(
        policy,
        {
            "schema",
            "fork",
            "repositorySettings",
            "consumerSnapshots",
            "formulaAudit",
            "caskAudit",
            "workflowPolicy",
            "canary",
        },
        "policy",
    )
    require(policy.get("schema") == SCHEMA, f"policy schema must be {SCHEMA}")

    fork = policy.get("fork")
    require(isinstance(fork, dict), "fork policy is required")
    require_exact_keys(
        fork,
        {
            "repository",
            "upstream",
            "defaultBranch",
            "originRemoteName",
            "originUrl",
            "upstreamRemoteName",
            "upstreamFetchUrl",
            "upstreamPushUrl",
            "pinnedCommit",
            "pinnedTree",
            "preservedUpstreamSnapshot",
        },
        "fork",
    )
    require(
        fork.get("repository") == "axiomlayer/homebrew-core",
        "unexpected fork repository",
    )
    require(
        fork.get("upstream") == "Homebrew/homebrew-core", "unexpected fork upstream"
    )
    require(fork.get("defaultBranch") == "main", "fork default branch must be main")
    require(fork.get("originRemoteName") == "origin", "origin remote name drifted")
    require(
        fork.get("originUrl") == "https://github.com/axiomlayer/homebrew-core.git",
        "origin remote URL drifted",
    )
    require(
        fork.get("upstreamRemoteName") == "upstream",
        "upstream remote name drifted",
    )
    require(
        fork.get("upstreamFetchUrl") == "https://github.com/Homebrew/homebrew-core.git",
        "upstream fetch URL drifted",
    )
    require(
        fork.get("upstreamPushUrl") == "DISABLED",
        "upstream push URL must remain disabled",
    )
    pin = validate_hex(fork.get("pinnedCommit"), 160, "fork.pinnedCommit")
    validate_hex(fork.get("pinnedTree"), 160, "fork.pinnedTree")
    snapshot = fork.get("preservedUpstreamSnapshot")
    require(isinstance(snapshot, dict), "preserved upstream snapshot is required")
    require_exact_keys(snapshot, {"branch", "commit", "tree"}, "fork snapshot")
    require(
        snapshot.get("branch") == "upstream-snapshot-20260915",
        "unexpected snapshot branch",
    )
    validate_hex(snapshot.get("commit"), 160, "snapshot.commit")
    validate_hex(snapshot.get("tree"), 160, "snapshot.tree")

    settings = policy.get("repositorySettings")
    require(isinstance(settings, dict), "repository settings policy is required")
    expected_settings = {
        "actionsEnabled": True,
        "allowedActions": "selected",
        "githubOwnedActionsAllowed": True,
        "verifiedActionsAllowed": False,
        "allowedActionPatterns": [],
        "shaPinningRequired": True,
        "repositorySecrets": 0,
        "environments": 0,
    }
    require(settings == expected_settings, "repository settings policy drifted")

    consumers = policy.get("consumerSnapshots")
    require(
        isinstance(consumers, dict) and set(consumers) == {"dotfiles", "margay"},
        "exactly dotfiles and margay consumer snapshots are required",
    )
    for consumer_name, consumer in consumers.items():
        require(
            isinstance(consumer, dict), f"{consumer_name} snapshot must be an object"
        )
        common_fields = {
            "repository",
            "pullRequest",
            "commit",
            "tree",
            "privateSource",
            "files",
        }
        consumer_fields = (
            common_fields
            | {
                "brewfileFormulaRoots",
                "bootstrapFormulaRoots",
                "bootstrapCaskAliases",
                "bootstrapSelectionWitnesses",
            }
            if consumer_name == "dotfiles"
            else common_fields
            | {
                "homebrewCoreCommit",
                "homebrewCaskCommit",
                "activeCasks",
                "deferredCasks",
            }
        )
        require_exact_keys(consumer, consumer_fields, f"{consumer_name} snapshot")
        require(
            type(consumer.get("pullRequest")) is int and consumer["pullRequest"] > 0,
            f"{consumer_name}.pullRequest must be a positive integer",
        )
        validate_hex(consumer.get("commit"), 160, f"{consumer_name}.commit")
        validate_hex(consumer.get("tree"), 160, f"{consumer_name}.tree")
        require(
            consumer.get("privateSource") is True,
            f"{consumer_name} must remain marked private",
        )
        files = consumer.get("files")
        require(
            isinstance(files, dict) and files,
            f"{consumer_name}.files must not be empty",
        )
        for file_path, anchor in files.items():
            require(
                isinstance(file_path, str)
                and file_path
                and not file_path.startswith("/")
                and all(part not in ("", ".", "..") for part in Path(file_path).parts),
                f"unsafe {consumer_name} file path",
            )
            require(
                isinstance(anchor, dict),
                f"{consumer_name}:{file_path} anchor must be an object",
            )
            require_exact_keys(
                anchor, {"blob", "sha256"}, f"{consumer_name}:{file_path} anchor"
            )
            validate_hex(anchor.get("blob"), 160, f"{consumer_name}:{file_path}.blob")
            validate_hex(
                anchor.get("sha256"), 256, f"{consumer_name}:{file_path}.sha256"
            )
    require(
        consumers["dotfiles"].get("repository") == "axiomlayer/dotfiles",
        "unexpected Dotfiles repository",
    )
    require(
        consumers["margay"].get("repository") == "axiomlayer/margay",
        "unexpected Margay repository",
    )

    dotfiles = consumers["dotfiles"]
    brewfile_roots = ordered_unique_strings(
        dotfiles.get("brewfileFormulaRoots"), "brewfileFormulaRoots"
    )
    bootstrap_roots = sorted_unique_strings(
        dotfiles.get("bootstrapFormulaRoots"), "bootstrapFormulaRoots"
    )
    witnesses = dotfiles.get("bootstrapSelectionWitnesses")
    require(isinstance(witnesses, dict), "bootstrap selection witnesses are required")
    aliases = dotfiles.get("bootstrapCaskAliases")
    require(
        aliases == {"docker": "docker-desktop"}, "unexpected bootstrap cask aliases"
    )
    require(
        set(witnesses) == set(bootstrap_roots) | set(aliases),
        "bootstrap witnesses must exactly cover formula roots and cask aliases",
    )
    require(
        all(isinstance(witness, str) and witness for witness in witnesses.values()),
        "bootstrap source witnesses must be non-empty strings",
    )

    formula_audit = policy.get("formulaAudit")
    require(isinstance(formula_audit, dict), "formula audit policy is required")
    require_exact_keys(
        formula_audit,
        {
            "roots",
            "dependencyPolicy",
            "systemDependencyPolicy",
            "artifactPolicy",
            "rejectNoCheck",
            "requireDeclaredSourceIntegrity",
            "normalizedSources",
        },
        "formula audit",
    )
    roots = sorted_unique_strings(formula_audit.get("roots"), "formulaAudit.roots")
    require(
        roots == sorted(set(brewfile_roots) | set(bootstrap_roots)),
        "formula roots do not equal the consumer-selected union",
    )
    require(
        formula_audit.get("rejectNoCheck") is True,
        "formula no-check rejection must remain enabled",
    )
    require(
        formula_audit.get("requireDeclaredSourceIntegrity") is True,
        "formula source integrity must remain required",
    )
    require(
        formula_audit.get("dependencyPolicy")
        == "recursive union of depends_on and uses_from_macos declarations"
        and formula_audit.get("systemDependencyPolicy")
        == "uses_from_macos names absent from the tap are recorded as platform providers"
        and formula_audit.get("artifactPolicy")
        == "inspect formula declarations only; never download source archives or bottles",
        "formula audit semantics drifted",
    )
    normalized_sources = formula_audit.get("normalizedSources")
    require(
        isinstance(normalized_sources, list),
        "formula normalized-source policy is required",
    )
    normalized_paths: list[str] = []
    for normalized in normalized_sources:
        require(
            isinstance(normalized, dict)
            and set(normalized) == {"path", "upstreamBlob", "normalizedBlob", "sha256"},
            "formula normalized-source entry drifted",
        )
        path = normalized.get("path")
        require(
            isinstance(path, str)
            and re.fullmatch(r"Formula/[a-z0-9]+/[A-Za-z0-9+_.@-]+\.rb", path)
            is not None,
            "formula normalized-source path is unsafe",
        )
        normalized_paths.append(path)
        validate_hex(normalized.get("upstreamBlob"), 160, f"{path} upstream blob")
        validate_hex(normalized.get("normalizedBlob"), 160, f"{path} normalized blob")
        validate_hex(normalized.get("sha256"), 256, f"{path} normalized SHA-256")
    require(
        normalized_paths
        == ["Formula/b/bash.rb", "Formula/g/go.rb", "Formula/r/readline.rb"],
        "formula normalized-source inventory drifted",
    )

    margay = consumers["margay"]
    require(
        margay.get("homebrewCoreCommit") == pin,
        "Margay core pin does not equal fork pin",
    )
    cask_audit = policy.get("caskAudit")
    require(isinstance(cask_audit, dict), "cask audit policy is required")
    require_exact_keys(
        cask_audit,
        {"repository", "commit", "tree", "artifactPolicy", "definitions"},
        "cask audit",
    )
    require(
        cask_audit.get("repository") == "Homebrew/homebrew-cask"
        and cask_audit.get("artifactPolicy")
        == "fetch cask definition bytes only; never follow app URLs or mirror artifacts",
        "cask audit semantics drifted",
    )
    cask_pin = validate_hex(cask_audit.get("commit"), 160, "caskAudit.commit")
    validate_hex(cask_audit.get("tree"), 160, "caskAudit.tree")
    require(
        margay.get("homebrewCaskCommit") == cask_pin,
        "Margay cask pin does not equal audit pin",
    )
    active = sorted_unique_strings(margay.get("activeCasks"), "margay.activeCasks")
    deferred = sorted_unique_strings(
        margay.get("deferredCasks"), "margay.deferredCasks"
    )
    definitions = cask_audit.get("definitions")
    require(
        isinstance(definitions, list) and definitions, "cask definitions are required"
    )
    definition_names: list[str] = []
    dispositions: dict[str, str] = {}
    for definition in definitions:
        require(isinstance(definition, dict), "cask definition must be an object")
        require_exact_keys(
            definition,
            {
                "name",
                "path",
                "blob",
                "sha256",
                "disposition",
                "minimumDeclaredSha256",
                "allowNoCheck",
            },
            "cask definition",
        )
        name = definition.get("name")
        require(
            isinstance(name, str)
            and re.fullmatch(r"[A-Za-z0-9+_.@-]+", name) is not None,
            "safe cask name is required",
        )
        definition_names.append(name)
        dispositions[name] = definition.get("disposition")
        validate_hex(definition.get("blob"), 160, f"cask {name} blob")
        validate_hex(definition.get("sha256"), 256, f"cask {name} sha256")
        require(
            definition.get("path") == f"Casks/{name[0]}/{name}.rb",
            f"unexpected path for cask {name}",
        )
        minimum_hashes = definition.get("minimumDeclaredSha256")
        require(
            type(minimum_hashes) is int and minimum_hashes >= 0,
            f"cask {name} minimum hash count must be a non-negative integer",
        )
        require(
            isinstance(definition.get("allowNoCheck"), bool),
            f"cask {name} no-check policy is required",
        )
        disposition = definition.get("disposition")
        require(
            disposition in {"active", "deferred"},
            f"cask {name} disposition is invalid",
        )
        if disposition == "active":
            require(
                definition["allowNoCheck"] is False and minimum_hashes >= 1,
                f"active cask {name} must require a declared SHA-256",
            )
        else:
            require(
                definition["allowNoCheck"] is True,
                f"deferred cask {name} must remain explicitly no-check",
            )
    require(
        definition_names == sorted(set(definition_names)),
        "cask definitions must be sorted and unique",
    )
    require(
        set(definition_names) == set(active) | set(deferred),
        "cask definitions must exactly cover active and deferred selections",
    )
    require(
        active
        == sorted(
            name
            for name, disposition in dispositions.items()
            if disposition == "active"
        ),
        "active cask policy drifted",
    )
    require(
        deferred
        == sorted(
            name
            for name, disposition in dispositions.items()
            if disposition == "deferred"
        ),
        "deferred cask policy drifted",
    )

    workflow = policy.get("workflowPolicy")
    require(isinstance(workflow, dict), "workflow policy is required")
    require_exact_keys(
        workflow,
        {
            "active",
            "requiredStatusCheck",
            "rulesetBootstrap",
            "verifierSha256",
            "archiveManifest",
            "representativeFormulae",
            "metadataEvaluation",
            "sensitiveInputPolicy",
            "allowedActions",
            "tokenPermissions",
            "forbidCredentials",
            "forbidEnvironments",
            "forbidMutation",
            "forbidHostInstallation",
            "forbidArtifactTransfer",
        },
        "workflow policy",
    )
    require(
        workflow.get("active") == [".github/workflows/axiomlayer-tap-integrity.yml"],
        "exactly one active workflow is permitted",
    )
    require(
        workflow.get("requiredStatusCheck") == "Required tap integrity authority",
        "terminal required status check drifted",
    )
    require(
        workflow.get("rulesetBootstrap")
        == {
            "phaseOne": {
                "targetBranch": "main",
                "noBypassActors": True,
                "blockDeletion": True,
                "blockNonFastForward": True,
                "requirePullRequest": True,
                "requiredApprovingReviews": 1,
                "requiredStatusChecks": [],
            },
            "phaseTwo": {
                "targetBranch": "main",
                "noBypassActors": True,
                "blockDeletion": True,
                "blockNonFastForward": True,
                "requirePullRequest": True,
                "requiredApprovingReviews": 1,
                "dismissStaleApprovals": True,
                "requireConversationResolution": True,
                "strictStatusChecks": True,
                "requiredStatusChecks": ["Required tap integrity authority"],
            },
        },
        "two-phase protected-main ruleset bootstrap drifted",
    )
    validate_hex(workflow.get("verifierSha256"), 256, "verifier SHA-256")
    require(
        workflow.get("allowedActions") == {}, "active workflow must not invoke Actions"
    )
    require(
        workflow.get("tokenPermissions") == "none",
        "workflow token permissions must be none",
    )
    for guard in (
        "forbidCredentials",
        "forbidEnvironments",
        "forbidMutation",
        "forbidHostInstallation",
        "forbidArtifactTransfer",
    ):
        require(workflow.get(guard) is True, f"{guard} must remain enabled")
    require(
        workflow.get("sensitiveInputPolicy") == "fabricated-only",
        "sensitive workflow inputs must remain fabricated-only",
    )
    require(
        workflow.get("representativeFormulae") == ["go", "jq", "ripgrep", "sqlite"],
        "representative formula evaluation set drifted",
    )
    require(
        workflow.get("metadataEvaluation")
        == {
            "mode": "static-source-declarations",
            "rubySourceExecution": False,
            "homebrewRuntimeLoaded": False,
            "homebrewStateMutationAllowed": False,
            "formulaHooksInvoked": False,
            "caskHooksInvoked": False,
        },
        "metadata-only evaluation policy drifted",
    )

    archive = workflow.get("archiveManifest")
    require(isinstance(archive, dict), "workflow archive manifest is required")
    require_exact_keys(
        archive,
        {"baselineCommit", "archiveRoot", "activeSha256", "readme", "entries"},
        "workflow archive manifest",
    )
    require(
        archive.get("baselineCommit") == pin,
        "workflow archive baseline must equal the immutable fork pin",
    )
    require(
        archive.get("archiveRoot") == ".github/upstream-workflows",
        "workflow archive root drifted",
    )
    active_workflow_sha256 = validate_hex(
        archive.get("activeSha256"), 256, "active workflow SHA-256"
    )
    if expected_active_workflow_sha256 is not None:
        require(
            active_workflow_sha256 == expected_active_workflow_sha256,
            "active workflow SHA-256 drifted from the verifier constant",
        )
    readme = archive.get("readme")
    require(isinstance(readme, dict), "workflow archive README anchor is required")
    require_exact_keys(readme, {"path", "sha256"}, "workflow archive README")
    require(
        readme.get("path") == ".github/upstream-workflows/README.md",
        "workflow archive README path drifted",
    )
    validate_hex(readme.get("sha256"), 256, "workflow archive README SHA-256")
    entries = archive.get("entries")
    require(
        isinstance(entries, list) and len(entries) == 30,
        "workflow archive manifest must contain all 30 baseline GitHub files",
    )
    source_paths: list[str] = []
    archive_paths: list[str] = []
    for entry in entries:
        require(isinstance(entry, dict), "workflow archive entry must be an object")
        require(
            set(entry) == {"sourcePath", "archivePath", "sha256"},
            "workflow archive entry fields drifted",
        )
        source_path = entry.get("sourcePath")
        archive_path = entry.get("archivePath")
        require(
            isinstance(source_path, str)
            and source_path.startswith(".github/")
            and ".." not in Path(source_path).parts,
            "unsafe workflow archive source path",
        )
        require(
            isinstance(archive_path, str)
            and archive_path.startswith(".github/upstream-workflows/")
            and archive_path.endswith(".disabled")
            and ".." not in Path(archive_path).parts,
            "unsafe workflow archive destination path",
        )
        validate_hex(entry.get("sha256"), 256, f"archive {source_path} SHA-256")
        source_paths.append(source_path)
        archive_paths.append(archive_path)
    require(
        source_paths == sorted(set(source_paths)),
        "workflow archive source paths must be sorted and unique",
    )
    require(
        len(archive_paths) == len(set(archive_paths)),
        "workflow archive destination paths must be unique",
    )

    canary = policy.get("canary")
    require(isinstance(canary, dict), "canary policy is required")
    require_exact_keys(
        canary, {"upstream", "ref", "automaticPromotion", "surfaces"}, "canary"
    )
    require(
        canary.get("upstream") == "https://github.com/Homebrew/homebrew-core.git",
        "unexpected canary upstream",
    )
    require(canary.get("ref") == "refs/heads/main", "canary must inspect upstream main")
    require(
        canary.get("automaticPromotion") is False,
        "canary promotion must remain disabled",
    )
    surfaces = canary.get("surfaces")
    require(
        isinstance(surfaces, list) and len(surfaces) == 4,
        "four architecture surfaces are required",
    )
    ids = [surface.get("id") for surface in surfaces if isinstance(surface, dict)]
    require(
        ids == ["linux-x86_64", "linux-aarch64", "darwin-x86_64", "darwin-arm64"],
        "canary surfaces drifted",
    )
    expected_surfaces = [
        {
            "id": "linux-x86_64",
            "runner": "ubuntu-24.04",
            "unameSystem": "Linux",
            "unameMachine": "x86_64",
        },
        {
            "id": "linux-aarch64",
            "runner": "ubuntu-24.04-arm",
            "unameSystem": "Linux",
            "unameMachine": "aarch64",
        },
        {
            "id": "darwin-x86_64",
            "runner": "macos-15-intel",
            "unameSystem": "Darwin",
            "unameMachine": "x86_64",
        },
        {
            "id": "darwin-arm64",
            "runner": "macos-15",
            "unameSystem": "Darwin",
            "unameMachine": "arm64",
        },
    ]
    for surface in surfaces:
        require(isinstance(surface, dict), "canary surface must be an object")
        require_exact_keys(
            surface, {"id", "runner", "unameSystem", "unameMachine"}, "canary surface"
        )
    require(surfaces == expected_surfaces, "canary runner/architecture mapping drifted")


def strip_ruby_comments(text: str) -> str:
    output: list[str] = []
    for line in text.splitlines():
        quote: str | None = None
        escaped = False
        clean: list[str] = []
        for character in line:
            if escaped:
                clean.append(character)
                escaped = False
                continue
            if character == "\\" and quote is not None:
                clean.append(character)
                escaped = True
                continue
            if character in ('"', "'"):
                if quote is None:
                    quote = character
                elif quote == character:
                    quote = None
                clean.append(character)
                continue
            if character == "#" and quote is None:
                break
            clean.append(character)
        output.append("".join(clean))
    return "\n".join(output)


def ruby_dsl_calls(text: str, label: str) -> list[dict[str, Any]]:
    """Parse bare Ruby DSL calls with Ripper without evaluating source code."""

    require(len(text.encode("utf-8")) <= 2_097_152, f"{label} is unexpectedly large")
    with tempfile.TemporaryDirectory(prefix="axiomlayer-ripper-") as temporary:
        result = subprocess.run(
            [
                ruby_executable(),
                "--disable-gems",
                "-rjson",
                "-rripper",
                "-e",
                RUBY_DSL_CALLS,
            ],
            check=False,
            input=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_ruby_environment(Path(temporary)),
        )
    require(
        result.returncode == 0,
        f"{label} is malformed Ruby: {result.stderr.strip()}",
    )
    try:
        calls = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise IntegrityViolation(f"{label} Ripper output is malformed") from error
    require(isinstance(calls, list), f"{label} Ripper output is not a call list")
    for call in calls:
        require(
            isinstance(call, dict)
            and set(call)
            == {
                "name",
                "line",
                "scope",
                "block",
                "strings",
                "stringPrefixes",
                "symbols",
                "named",
                "argument",
            }
            and isinstance(call["name"], str)
            and type(call["line"]) is int
            and call["line"] > 0
            and isinstance(call["scope"], list)
            and all(isinstance(item, str) for item in call["scope"])
            and isinstance(call["block"], bool)
            and isinstance(call["strings"], list)
            and all(isinstance(item, str) for item in call["strings"])
            and isinstance(call["stringPrefixes"], list)
            and all(isinstance(item, str) for item in call["stringPrefixes"])
            and isinstance(call["symbols"], list)
            and all(isinstance(item, str) for item in call["symbols"])
            and isinstance(call["named"], dict),
            f"{label} Ripper call record is malformed",
        )
        argument = call["argument"]
        require(
            isinstance(argument, dict)
            and set(argument) == {"kind", "value", "entries"}
            and argument["kind"]
            in {
                "none",
                "literal",
                "literalWithOptions",
                "symbol",
                "constant",
                "map",
                "dynamic",
            }
            and (argument["value"] is None or isinstance(argument["value"], str))
            and isinstance(argument["entries"], list),
            f"{label} Ripper argument record is malformed",
        )
        for entry in argument["entries"]:
            require(
                isinstance(entry, dict)
                and set(entry) == {"keyKind", "key", "valueKind", "value"}
                and entry["keyKind"] in {"label", "symbol", "string", "dynamic"}
                and (entry["key"] is None or isinstance(entry["key"], str))
                and entry["valueKind"] in {"literal", "symbol", "dynamic"}
                and (entry["value"] is None or isinstance(entry["value"], str)),
                f"{label} Ripper map entry is malformed",
            )
    return calls


def formula_release_calls(text: str, label: str) -> list[dict[str, Any]]:
    ignored_blocks = {"bottle", "head", "livecheck", "service", "test"}
    return [
        call
        for call in ruby_dsl_calls(text, label)
        if not ignored_blocks.intersection(
            scope.split("@", 1)[0] for scope in call["scope"]
        )
    ]


def declared_sha256_values(
    calls: Iterable[dict[str, Any]], label: str
) -> tuple[list[str], bool]:
    """Accept only concrete direct SHA literals or an exact architecture map."""

    values: list[str] = []
    no_check = False
    for call in calls:
        if call["name"] != "sha256":
            continue
        argument = call["argument"]
        if argument["kind"] == "symbol":
            require(
                argument["value"] == "no_check",
                f"{label} has malformed sha256 symbol {argument['value']!r}",
            )
            no_check = True
            continue
        if argument["kind"] == "literal":
            literal = argument["value"]
            require(
                isinstance(literal, str) and HEX64.fullmatch(literal) is not None,
                f"{label} has malformed sha256 {literal!r}",
            )
            values.append(literal)
            continue
        if argument["kind"] == "map":
            entries = argument["entries"]
            keys = [entry["key"] for entry in entries]
            require(
                len(entries) == 2
                and set(keys) == {"arm", "intel"}
                and len(set(keys)) == len(keys)
                and all(entry["keyKind"] in {"label", "symbol"} for entry in entries),
                f"{label} sha256 architecture map must contain exactly arm and intel",
            )
            for entry in entries:
                literal = entry["value"]
                require(
                    entry["valueKind"] == "literal"
                    and isinstance(literal, str)
                    and HEX64.fullmatch(literal) is not None,
                    f"{label} has malformed sha256 architecture value",
                )
                values.append(literal)
            continue
        raise IntegrityViolation(f"{label} has dynamic or malformed sha256 declaration")
    return values, no_check


def declared_formula_dependencies(
    calls: Iterable[dict[str, Any]], call_name: str, label: str
) -> list[str]:
    """Extract direct static formula names from genuine dependency DSL calls."""

    values: list[str] = []
    for call in calls:
        if call["name"] != call_name:
            continue
        argument = call["argument"]
        if argument["kind"] in {"literal", "literalWithOptions"}:
            require(
                isinstance(argument["value"], str),
                f"{label} has malformed {call_name} dependency",
            )
            values.append(argument["value"])
            continue
        if argument["kind"] == "map":
            string_entries = [
                entry for entry in argument["entries"] if entry["keyKind"] == "string"
            ]
            if string_entries:
                require(
                    len(argument["entries"]) == 1 and len(string_entries) == 1,
                    f"{label} has ambiguous {call_name} formula dependency",
                )
                values.append(string_entries[0]["key"])
            continue
        if call_name == "depends_on" and argument["kind"] in {
            "symbol",
            "constant",
        }:
            continue
        require(
            argument["kind"] != "dynamic",
            f"{label} has dynamic {call_name} dependency",
        )
    return values


def declared_cask_dependencies(
    calls: Iterable[dict[str, Any]], dependency_kind: str, label: str
) -> list[str]:
    """Extract an exact static cask ``depends_on <kind>:`` declaration."""

    values: list[str] = []
    for call in calls:
        if call["name"] != "depends_on" or call["argument"]["kind"] != "map":
            continue
        for entry in call["argument"]["entries"]:
            if entry["key"] != dependency_kind:
                continue
            require(
                entry["keyKind"] in {"label", "symbol"}
                and entry["valueKind"] == "literal"
                and isinstance(entry["value"], str),
                f"{label} has malformed {dependency_kind} dependency",
            )
            values.append(entry["value"])
    return values


def source_url_calls(calls: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        call
        for call in calls
        if call["name"] == "url"
        and any(
            re.match(r"^https?://", value)
            for value in set(call["strings"]) | set(call["stringPrefixes"])
        )
    ]


def revision_values(call: dict[str, Any], label: str) -> list[str]:
    named = call["named"].get("revision")
    if named is None:
        return []
    require(
        isinstance(named, dict)
        and set(named) == {"strings", "symbols"}
        and isinstance(named["strings"], list)
        and isinstance(named["symbols"], list)
        and not named["symbols"],
        f"{label} has a malformed revision declaration",
    )
    for revision in named["strings"]:
        require(
            re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is not None,
            f"{label} has malformed revision {revision!r}",
        )
    return named["strings"]


def validate_scoped_source_integrity(
    calls: Iterable[dict[str, Any]], label: str
) -> None:
    """Require every parsed Ruby DSL URL scope to carry parsed integrity."""

    scopes: dict[tuple[str, ...], dict[str, int]] = {}
    for call in calls:
        scope = tuple(call["scope"])
        record = scopes.setdefault(scope, {"urls": 0, "integrity": 0})
        if call in source_url_calls([call]):
            record["urls"] += 1
            record["integrity"] += len(revision_values(call, label))
        if call["name"] == "sha256":
            hashes, no_check = declared_sha256_values([call], label)
            record["integrity"] += len(hashes)
    missing = [
        scope
        for scope, record in scopes.items()
        if record["urls"] and not record["integrity"]
    ]
    require(not missing, f"{label} has a source block without declared integrity")


def strip_nonrelease_formula_blocks(text: str) -> str:
    """Remove DSL blocks that do not describe the selected stable release.

    Homebrew's formatter gives a named block and its closing ``end`` the same
    indentation. Using that invariant avoids executing Ruby while excluding
    head-only dependencies and metadata/test URLs from the stable audit.
    """

    ignored = {"bottle", "head", "livecheck", "service", "test"}
    lines = text.splitlines()
    output: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)([a-z_]+)\b.*\bdo\s*(?:\|[^|]*\|)?\s*$", line)
        if not match or match.group(2) not in ignored:
            output.append(line)
            index += 1
            continue
        indentation = match.group(1)
        index += 1
        closing = re.compile(rf"^{re.escape(indentation)}end\s*$")
        while index < len(lines) and closing.match(lines[index]) is None:
            index += 1
        require(
            index < len(lines), f"unterminated ignored formula block: {match.group(2)}"
        )
        index += 1
    return "\n".join(output)


def formula_name_from_dependency(name: str) -> str:
    require(
        not name.startswith("/"), f"absolute formula dependency is forbidden: {name}"
    )
    parts = name.split("/")
    require(
        all(part not in ("", ".", "..") for part in parts),
        f"unsafe formula dependency: {name}",
    )
    return parts[-1]


def require_no_symlink_ancestry(root: Path, candidate: Path, label: str) -> None:
    require(root.is_dir() and not root.is_symlink(), f"{label} root is unsafe: {root}")
    require(
        candidate.is_relative_to(root), f"{label} path escapes its root: {candidate}"
    )
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        require(not current.is_symlink(), f"{label} path contains a symlink: {current}")


def formula_path(tap_root: Path, requested_name: str) -> Path | None:
    name = formula_name_from_dependency(requested_name)
    formula_root = tap_root / "Formula"
    require(
        formula_root.is_dir() and not formula_root.is_symlink(),
        f"Formula root is absent or unsafe: {formula_root}",
    )
    shard = "lib" if name.startswith("lib") else name[0].lower()
    direct = formula_root / shard / f"{name}.rb"
    if direct.exists() or direct.is_symlink():
        require_no_symlink_ancestry(formula_root, direct, f"formula {name}")
        try:
            resolved_direct = direct.resolve(strict=True)
        except OSError as error:
            raise IntegrityViolation(f"unsafe formula path {name}: {error}") from error
        resolved_formula_root = formula_root.resolve(strict=True)
        require(
            resolved_direct.is_relative_to(resolved_formula_root),
            f"formula path escapes Formula/: {name} -> {resolved_direct}",
        )
        require(resolved_direct.is_file(), f"formula path is not a file: {name}")
        return resolved_direct
    aliases_root = tap_root / "Aliases"
    require(
        aliases_root.is_dir() and not aliases_root.is_symlink(),
        f"Aliases root is absent or unsafe: {aliases_root}",
    )
    alias = aliases_root / name
    if not alias.exists():
        return None
    try:
        resolved = alias.resolve(strict=True)
    except OSError as error:
        raise IntegrityViolation(f"broken formula alias {name}: {error}") from error
    root = tap_root.resolve()
    require(
        resolved.is_relative_to(root / "Formula"),
        f"formula alias escapes Formula/: {name} -> {resolved}",
    )
    require(resolved.is_file(), f"formula alias target is not a file: {name}")
    return resolved


def formula_bytes_for_audit(
    tap_root: Path,
    path: Path,
    *,
    policy: dict[str, Any] | None = None,
    normalization_root: Path | None = None,
) -> bytes:
    """Read source or its exact reviewed normalization without mutating the tap."""

    data = path.read_bytes()
    if policy is None or normalization_root is None:
        return data
    relative = path.relative_to(tap_root).as_posix()
    entries = {
        entry["path"]: entry for entry in policy["formulaAudit"]["normalizedSources"]
    }
    entry = entries.get(relative)
    if entry is None:
        return data
    require(
        git_blob_id(data) == entry["upstreamBlob"],
        f"upstream source requires a new reviewed normalization: {relative}",
    )
    normalized_path = normalization_root / relative
    require_no_symlink_ancestry(
        normalization_root, normalized_path, f"normalized audit source {relative}"
    )
    require(
        normalized_path.is_file() and not normalized_path.is_symlink(),
        f"normalized audit source is absent or unsafe: {relative}",
    )
    normalized = normalized_path.read_bytes()
    require(
        git_blob_id(normalized) == entry["normalizedBlob"]
        and sha256_bytes(normalized) == entry["sha256"],
        f"normalized audit source bytes drifted: {relative}",
    )
    return normalized


def audit_formula_source(name: str, path: Path, text: str) -> tuple[int, int]:
    label = f"formula {name}"
    calls = formula_release_calls(text, label)
    urls = source_url_calls(calls)
    hashes, no_check = declared_sha256_values(calls, label)
    require(not no_check, f"formula {name} uses sha256 :no_check")
    revisions = [revision for call in urls for revision in revision_values(call, label)]
    require(urls, f"formula {name} has no declared HTTPS source URL ({path})")
    require(
        hashes or revisions,
        f"formula {name} has no declared source digest or revision ({path})",
    )
    validate_scoped_source_integrity(calls, label)
    return len(urls), len(hashes) + len(revisions)


def audit_formula_closure(
    tap_root: Path,
    roots: Iterable[str],
    *,
    policy: dict[str, Any] | None = None,
    normalization_root: Path | None = None,
) -> dict[str, Any]:
    require(
        tap_root.is_dir() and not tap_root.is_symlink(),
        f"tap root is absent or unsafe: {tap_root}",
    )
    tap_root = tap_root.resolve(strict=True)
    require(
        (tap_root / "Formula").is_dir() and not (tap_root / "Formula").is_symlink(),
        "tap Formula root is absent or unsafe",
    )
    require(
        (tap_root / "Aliases").is_dir() and not (tap_root / "Aliases").is_symlink(),
        "tap Aliases root is absent or unsafe",
    )
    queue = deque(sorted(set(roots)))
    seen: set[str] = set()
    aliases: dict[str, str] = {}
    system_dependencies: set[str] = set()
    records: list[tuple[str, str, str]] = []
    source_urls = 0
    integrity_tokens = 0

    while queue:
        requested = queue.popleft()
        name = formula_name_from_dependency(requested)
        path = formula_path(tap_root, name)
        require(path is not None, f"formula dependency is absent from tap: {name}")
        canonical_name = path.stem
        if name != canonical_name:
            aliases[name] = canonical_name
        if canonical_name in seen:
            continue
        data = formula_bytes_for_audit(
            tap_root,
            path,
            policy=policy,
            normalization_root=normalization_root,
        )
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise IntegrityViolation(f"formula is not UTF-8: {path}") from error
        urls, tokens = audit_formula_source(canonical_name, path, text)
        source_urls += urls
        integrity_tokens += tokens
        calls = formula_release_calls(text, f"formula {canonical_name}")
        for dependency in declared_formula_dependencies(
            calls, "depends_on", f"formula {canonical_name}"
        ):
            dependency_name = formula_name_from_dependency(dependency)
            require(
                formula_path(tap_root, dependency_name) is not None,
                f"{canonical_name} depends on missing formula {dependency_name}",
            )
            if dependency_name not in seen:
                queue.append(dependency_name)
        for dependency in declared_formula_dependencies(
            calls, "uses_from_macos", f"formula {canonical_name}"
        ):
            dependency_name = formula_name_from_dependency(dependency)
            if formula_path(tap_root, dependency_name) is None:
                system_dependencies.add(dependency_name)
            elif dependency_name not in seen:
                queue.append(dependency_name)
        relative = path.relative_to(tap_root).as_posix()
        records.append((canonical_name, relative, sha256_bytes(data)))
        seen.add(canonical_name)

    records.sort()
    closure_material = "".join(
        f"{name}\0{path}\0{digest}\n" for name, path, digest in records
    ).encode("utf-8")
    return {
        "formulaCount": len(records),
        "formulaClosureSha256": sha256_bytes(closure_material),
        "sourceUrlDeclarations": source_urls,
        "integrityDeclarations": integrity_tokens,
        "selectedAliases": dict(sorted(aliases.items())),
        "systemDependencies": sorted(system_dependencies),
        "formulae": [name for name, _, _ in records],
    }


def audit_representative_formulae(
    tap_root: Path,
    names: Iterable[str],
    *,
    policy: dict[str, Any] | None = None,
    normalization_root: Path | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for requested_name in names:
        path = formula_path(tap_root, requested_name)
        require(path is not None, f"representative formula is absent: {requested_name}")
        data = formula_bytes_for_audit(
            tap_root,
            path,
            policy=policy,
            normalization_root=normalization_root,
        )
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise IntegrityViolation(
                f"representative formula is not UTF-8: {requested_name}"
            ) from error
        clean = strip_nonrelease_formula_blocks(strip_ruby_comments(text))
        urls, integrity_tokens = audit_formula_source(requested_name, path, text)
        require(
            re.search(r"(?m)^\s*def\s+install\b", clean) is not None,
            f"representative formula has no declared install hook: {requested_name}",
        )
        records.append(
            {
                "name": requested_name,
                "path": path.relative_to(tap_root.resolve()).as_posix(),
                "sha256": sha256_bytes(data),
                "sourceUrlDeclarations": urls,
                "integrityDeclarations": integrity_tokens,
                "installHookDeclared": True,
                "installHookInvoked": False,
                "rubySourceExecuted": False,
            }
        )
    return records


def repository_state(repo: Path) -> dict[str, str]:
    return {
        "head": git_output(repo, "rev-parse", "HEAD"),
        "tree": git_output(repo, "rev-parse", "HEAD^{tree}"),
        "status": git_output(repo, "status", "--porcelain=v1", "--untracked-files=all"),
    }


def allowed_integration_path(path: str, policy: dict[str, Any]) -> bool:
    workflow = policy["workflowPolicy"]
    if path.startswith("axiomlayer/") or path in workflow["active"]:
        return True
    if path in {entry["path"] for entry in policy["formulaAudit"]["normalizedSources"]}:
        return True
    archive = workflow["archiveManifest"]
    if path == archive["readme"]["path"]:
        return True
    for entry in archive["entries"]:
        if path in (entry["sourcePath"], entry["archivePath"]):
            return True
    return False


def verify_checkout_base(repo: Path, protected_main_head: str) -> None:
    """Bind a PR merge checkout to the exact current protected fork base."""

    validate_hex(protected_main_head, 160, "protected fork main")
    head = git_output(repo, "rev-parse", "HEAD")
    if head == protected_main_head:
        return
    parents = git_output(repo, "rev-list", "--parents", "-n", "1", head).split()
    require(
        len(parents) >= 3 and parents[1] == protected_main_head,
        "pull-request checkout is not based on current protected fork main",
    )


def verify_pin_history(
    repo: Path,
    policy: dict[str, Any],
    *,
    protected_main_head: str | None = None,
) -> None:
    repo = repo.resolve()
    fork = policy["fork"]
    pin = fork["pinnedCommit"]
    head = git_output(repo, "rev-parse", "HEAD")
    if protected_main_head is not None:
        verify_checkout_base(repo, protected_main_head)
    require(
        git(repo, "cat-file", "-e", f"{pin}^{{commit}}", check=False).returncode == 0,
        f"pinned commit is absent: {pin}",
    )
    actual_tree = git_output(repo, "rev-parse", f"{pin}^{{tree}}")
    require(
        actual_tree == fork["pinnedTree"],
        f"pinned tree mismatch: expected {fork['pinnedTree']}, got {actual_tree}",
    )
    require(
        git(repo, "merge-base", "--is-ancestor", pin, head, check=False).returncode
        == 0,
        "Margay's pinned commit is not an ancestor of HEAD",
    )
    changed = git_output(repo, "diff", "--name-only", pin, head).splitlines()
    unexpected = sorted(
        path for path in changed if path and not allowed_integration_path(path, policy)
    )
    require(
        not unexpected,
        f"integration branch changes tap content outside its lane: {unexpected}",
    )
    remote_names = git_output(repo, "remote").splitlines()
    require(
        remote_names == ["origin", "upstream"],
        f"Git remote names must be exactly origin and upstream, got {remote_names}",
    )
    origin = git_output(repo, "remote", "get-url", "origin")
    require(
        origin == "https://github.com/axiomlayer/homebrew-core.git",
        f"origin must be the AxiomLayer HTTPS fork, got {origin}",
    )
    require(
        git_output(repo, "remote", "get-url", "--push", "origin") == origin,
        "origin push URL must equal the exact AxiomLayer HTTPS fork",
    )
    upstream = git_output(repo, "remote", "get-url", "upstream")
    require(
        upstream == "https://github.com/Homebrew/homebrew-core.git",
        f"upstream fetch URL drifted: {upstream}",
    )
    require(
        git_output(repo, "remote", "get-url", "--push", "upstream") == "DISABLED",
        "upstream push URL must remain disabled",
    )


def public_json(url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    require(
        parsed.scheme == "https" and parsed.hostname == "api.github.com",
        f"refusing non-GitHub API URL: {url}",
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AxiomLayer-homebrew-tap-integrity/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            require(
                response.status == 200,
                f"GitHub API returned HTTP {response.status}: {url}",
            )
            body = response.read(1_048_577)
    except (OSError, urllib.error.HTTPError) as error:
        raise IntegrityViolation(
            f"cannot read public GitHub metadata {url}: {error}"
        ) from error
    require(len(body) <= 1_048_576, f"GitHub API response is unexpectedly large: {url}")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise IntegrityViolation(f"GitHub API response is not JSON: {url}") from error
    require(isinstance(value, dict), f"GitHub API response is not an object: {url}")
    return value


def verify_remote_fork(repo: Path, policy: dict[str, Any]) -> str:
    """Authenticate candidate, checkout base, and current fork independently."""

    fork = policy["fork"]
    metadata = public_json("https://api.github.com/repos/axiomlayer/homebrew-core")
    require(
        metadata.get("fork") is True,
        "axiomlayer/homebrew-core is not a true GitHub fork",
    )
    require(
        str(metadata.get("full_name", "")) == fork["repository"],
        "fork full name drifted",
    )
    require(
        str((metadata.get("parent") or {}).get("full_name", "")) == fork["upstream"],
        "fork parent drifted",
    )
    require(
        str((metadata.get("source") or {}).get("full_name", "")) == fork["upstream"],
        "fork source drifted",
    )
    require(
        metadata.get("default_branch") == fork["defaultBranch"],
        "fork default branch drifted",
    )

    snapshot = fork["preservedUpstreamSnapshot"]
    remote_url = "https://github.com/axiomlayer/homebrew-core.git"
    refs = git_remote_refs(
        remote_url, ["refs/heads/main", f"refs/heads/{snapshot['branch']}"]
    )
    main_head = refs.get("refs/heads/main")
    require(isinstance(main_head, str), "fork main ref is absent")
    require(
        refs.get(f"refs/heads/{snapshot['branch']}") == snapshot["commit"],
        "preserved upstream snapshot ref drifted",
    )
    upstream_url = "https://github.com/Homebrew/homebrew-core.git"
    verify_commit_on_remote_ref(
        upstream_url,
        "refs/heads/main",
        fork["pinnedCommit"],
        fork["pinnedTree"],
        "candidate policy pin",
    )
    verify_commit_on_remote_ref(
        upstream_url,
        "refs/heads/main",
        snapshot["commit"],
        snapshot["tree"],
        "preserved upstream snapshot",
    )
    verify_current_fork_main(remote_url, main_head)
    verify_pin_history(repo, policy, protected_main_head=main_head)
    return main_head


def git_remote_refs(remote_url: str, refs: list[str]) -> dict[str, str]:
    require(
        remote_url.startswith("https://github.com/"),
        f"refusing non-GitHub Git remote: {remote_url}",
    )
    with tempfile.TemporaryDirectory(prefix="axiomlayer-git-home-") as temporary:
        result = subprocess.run(
            ["git", "ls-remote", "--exit-code", remote_url, *refs],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_git_environment(Path(temporary)),
        )
    if result.returncode != 0:
        raise IntegrityViolation(
            f"cannot resolve public Git refs at {remote_url}: {result.stderr.strip()}"
        )
    resolved: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        require(
            len(fields) == 2 and HEX40.fullmatch(fields[0]) is not None,
            f"malformed ls-remote result: {line}",
        )
        require(fields[1] not in resolved, f"duplicate ls-remote ref: {fields[1]}")
        resolved[fields[1]] = fields[0]
    require(set(resolved) == set(refs), "Git remote did not return every exact ref")
    return resolved


def remote_commit_trees(remote_url: str, commits: list[str]) -> dict[str, str]:
    require(
        remote_url.startswith("https://github.com/"),
        f"refusing non-GitHub Git remote: {remote_url}",
    )
    for commit in commits:
        validate_hex(commit, 160, "remote commit")
    with tempfile.TemporaryDirectory(prefix="axiomlayer-git-metadata-") as temporary:
        repo = Path(temporary)
        git(repo, "init")
        git(repo, "remote", "add", "source", remote_url)
        trees: dict[str, str] = {}
        for commit in commits:
            git(
                repo,
                "fetch",
                "--no-tags",
                "--depth=1",
                "--filter=blob:none",
                "source",
                commit,
            )
            require(
                git_output(repo, "rev-parse", "FETCH_HEAD") == commit,
                f"fetched commit binding drifted for {commit}",
            )
            trees[commit] = git_output(repo, "rev-parse", "FETCH_HEAD^{tree}")
        return trees


def commit_is_ancestor(repo: Path, ancestor: str, head: str) -> bool:
    if git(repo, "cat-file", "-e", f"{ancestor}^{{commit}}", check=False).returncode:
        return False
    return (
        git(repo, "merge-base", "--is-ancestor", ancestor, head, check=False).returncode
        == 0
    )


def fetch_ref_with_dynamic_history(
    repo: Path,
    remote_name: str,
    ref: str,
    required_ancestors: Iterable[str],
) -> str:
    """Fetch enough history to prove ancestry, with no fixed shallow-depth ceiling."""

    require(
        re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", ref) is not None
        and ".." not in ref
        and not ref.endswith("/"),
        f"unsafe Git branch ref: {ref}",
    )
    ancestors = list(required_ancestors)
    for ancestor in ancestors:
        validate_hex(ancestor, 160, "required remote ancestor")
    step = 64
    git(
        repo,
        "fetch",
        "--no-tags",
        f"--depth={step}",
        "--filter=blob:none",
        remote_name,
        ref,
    )
    head = git_output(repo, "rev-parse", "FETCH_HEAD")
    validate_hex(head, 160, "fetched remote head")
    while not all(commit_is_ancestor(repo, ancestor, head) for ancestor in ancestors):
        if git_output(repo, "rev-parse", "--is-shallow-repository") != "true":
            break
        git(
            repo,
            "fetch",
            "--no-tags",
            f"--deepen={step}",
            "--filter=blob:none",
            remote_name,
            ref,
        )
        require(
            git_output(repo, "rev-parse", "FETCH_HEAD") == head,
            f"{remote_name} changed {ref} during provenance verification",
        )
        step *= 2
    missing = [
        ancestor
        for ancestor in ancestors
        if not commit_is_ancestor(repo, ancestor, head)
    ]
    require(
        not missing,
        f"{remote_name} {ref} does not contain required commit(s): {missing}",
    )
    return head


def verify_commit_on_remote_ref(
    remote_url: str,
    ref: str,
    commit: str,
    expected_tree: str,
    label: str,
) -> None:
    """Bind a candidate commit/tree directly to a named upstream history."""

    validate_hex(commit, 160, f"{label} commit")
    validate_hex(expected_tree, 160, f"{label} tree")
    with tempfile.TemporaryDirectory(prefix="axiomlayer-fork-history-") as temporary:
        repo = Path(temporary)
        git(repo, "init")
        git(repo, "remote", "add", "source", remote_url)
        fetch_ref_with_dynamic_history(repo, "source", ref, [commit])
        require(
            git_output(repo, "rev-parse", f"{commit}^{{tree}}") == expected_tree,
            f"{label} tree drifted",
        )


def policy_from_commit(repo: Path, commit: str) -> dict[str, Any] | None:
    path = "axiomlayer/tap-integrity-policy.json"
    if git(repo, "cat-file", "-e", f"{commit}:{path}", check=False).returncode:
        return None
    data = git_bytes(repo, "show", f"{commit}:{path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IntegrityViolation("protected fork policy is not UTF-8") from error
    return parse_json_object(text, "protected fork policy")


def verify_current_fork_main(remote_url: str, head: str) -> None:
    """Verify current protected fork main without using the candidate's pin."""

    validate_hex(head, 160, "current fork main")
    with tempfile.TemporaryDirectory(prefix="axiomlayer-current-fork-") as temporary:
        repo = Path(temporary)
        git(repo, "init")
        git(repo, "remote", "add", "origin", remote_url)
        fetched = fetch_ref_with_dynamic_history(repo, "origin", "refs/heads/main", [])
        require(fetched == head, "fork main changed during provenance verification")
        current_policy = policy_from_commit(repo, head)
        if current_policy is None:
            tree = git_output(repo, "rev-parse", f"{head}^{{tree}}")
            verify_commit_on_remote_ref(
                "https://github.com/Homebrew/homebrew-core.git",
                "refs/heads/main",
                head,
                tree,
                "pre-integration fork main",
            )
            return

        validate_policy(current_policy, expected_active_workflow_sha256=None)
        pin = current_policy["fork"]["pinnedCommit"]
        fetch_ref_with_dynamic_history(repo, "origin", "refs/heads/main", [pin])
        require(
            git_output(repo, "rev-parse", f"{pin}^{{tree}}")
            == current_policy["fork"]["pinnedTree"],
            "current fork main pin tree drifted",
        )
        changed = git_output(repo, "diff", "--name-only", pin, head).splitlines()
        unexpected = sorted(
            path
            for path in changed
            if path and not allowed_integration_path(path, current_policy)
        )
        require(
            not unexpected,
            f"current fork main changes tap content outside its integration lane: {unexpected}",
        )
        git(repo, "-c", "advice.detachedHead=false", "checkout", "--detach", head)
        verifier_path = repo / "axiomlayer" / "verify_tap_integrity.py"
        require(
            sha256_bytes(verifier_path.read_bytes())
            == current_policy["workflowPolicy"]["verifierSha256"],
            "current fork main verifier digest drifted",
        )
        workflow_paths = git_output(
            repo, "ls-tree", "-r", "--name-only", head, ".github/workflows"
        ).splitlines()
        require(
            workflow_paths == current_policy["workflowPolicy"]["active"],
            f"current fork main active workflows drifted: {workflow_paths}",
        )
        require(
            sha256_bytes(
                (repo / current_policy["workflowPolicy"]["active"][0]).read_bytes()
            )
            == current_policy["workflowPolicy"]["archiveManifest"]["activeSha256"],
            "current fork main active workflow digest drifted",
        )
        verify_archive(repo, current_policy)
        verify_commit_on_remote_ref(
            "https://github.com/Homebrew/homebrew-core.git",
            "refs/heads/main",
            pin,
            current_policy["fork"]["pinnedTree"],
            "current fork main policy pin",
        )


def baseline_automation_paths(repo: Path, baseline: str) -> list[str]:
    return sorted(
        git_output(
            repo, "ls-tree", "-r", "--name-only", baseline, ".github"
        ).splitlines()
    )


def verify_archive(repo: Path, policy: dict[str, Any]) -> None:
    archive = policy["workflowPolicy"]["archiveManifest"]
    baseline = archive["baselineCommit"]
    entries = archive["entries"]
    source_paths = [entry["sourcePath"] for entry in entries]
    require(
        source_paths == baseline_automation_paths(repo, baseline),
        "archive manifest does not cover every baseline GitHub file",
    )

    expected_files = {archive["readme"]["path"]}
    expected_files.update(entry["archivePath"] for entry in entries)
    archive_root = repo / archive["archiveRoot"]
    require(
        archive_root.is_dir() and not archive_root.is_symlink(),
        "workflow archive root is absent or unsafe",
    )
    actual_files = {
        path.relative_to(repo).as_posix()
        for path in archive_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    require(
        actual_files == expected_files,
        f"workflow archive inventory drifted: {sorted(actual_files ^ expected_files)}",
    )

    readme_path = repo / archive["readme"]["path"]
    require(
        readme_path.is_file() and not readme_path.is_symlink(),
        "workflow archive README is absent or unsafe",
    )
    require(
        sha256_bytes(readme_path.read_bytes()) == archive["readme"]["sha256"],
        "workflow archive README digest drifted",
    )

    for entry in entries:
        source_path = entry["sourcePath"]
        archive_path = repo / entry["archivePath"]
        require(
            not (repo / source_path).exists() and not (repo / source_path).is_symlink(),
            f"baseline automation was reactivated at {source_path}",
        )
        require(
            archive_path.is_file() and not archive_path.is_symlink(),
            f"workflow archive entry is absent or unsafe: {entry['archivePath']}",
        )
        archived_bytes = archive_path.read_bytes()
        require(
            sha256_bytes(archived_bytes) == entry["sha256"],
            f"workflow archive digest drifted: {entry['archivePath']}",
        )
        baseline_bytes = git_bytes(repo, "show", f"{baseline}:{source_path}")
        require(
            archived_bytes == baseline_bytes,
            f"workflow archive differs byte-for-byte from baseline: {entry['archivePath']}",
        )
        baseline_mode, baseline_type, baseline_object = git_tree_entry(
            repo, baseline, source_path
        )
        archive_mode, archive_object = git_index_entry(repo, entry["archivePath"])
        expected_object = git_blob_id(archived_bytes)
        require(
            baseline_type == "blob"
            and baseline_object == expected_object
            and archive_object == expected_object,
            f"workflow archive Git object drifted: {entry['archivePath']}",
        )
        require(
            archive_mode == baseline_mode,
            f"workflow archive mode drifted: {entry['archivePath']}",
        )


def verify_active_workflow(repo: Path, policy: dict[str, Any]) -> None:
    workflow_policy = policy["workflowPolicy"]
    workflow_root = repo / ".github" / "workflows"
    active = sorted(
        path.relative_to(repo).as_posix()
        for path in workflow_root.rglob("*")
        if path.is_file() or path.is_symlink()
    )
    require(active == workflow_policy["active"], f"active workflows drifted: {active}")

    forbidden_fragments = (
        "${{ secrets.",
        "secrets",
        "github.token",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "${{ vars.",
        "${{ inputs.",
        "github.event.inputs",
        "pull_request_target:",
        "repository_dispatch:",
        "workflow_run:",
        "contents: write",
        "packages: write",
        "id-token: write",
        "actions: write",
        "checks: write",
        "issues: write",
        "pull-requests: write",
        "deployments: write",
        "upload-artifact",
        "download-artifact",
        "brew install",
        "brew upgrade",
        "brew bump",
        "brew bottle",
        "git push",
        "gh pr ",
        "gh release ",
        "curl ",
        "wget ",
        "pip install",
        "apt-get",
        "continue-on-error:",
        "permissions: write-all",
        "Formulary",
        "brew ruby",
        "bin/brew",
        "jsr.io",
        "jsr:",
        "--skip-remote-fork",
        "--skip-casks",
    )
    for relative in active:
        path = repo / relative
        require(
            not path.is_symlink(), f"active workflow must not be a symlink: {relative}"
        )
        text = path.read_text(encoding="utf-8")
        require(
            sha256_bytes(text.encode("utf-8"))
            == workflow_policy["archiveManifest"]["activeSha256"],
            f"{relative} digest drifted",
        )
        verify_unambiguous_yaml(text, relative)
        require(
            text.count(f"    if: {PINNED_POLICY_CONDITION}") == 1,
            f"{relative} pinned-policy event guard drifted",
        )
        require(
            text.count(f"    if: {CANARY_CONDITION}") == 1,
            f"{relative} canary event guard drifted",
        )
        required_markers = (
            "  workflow-required:\n",
            "    name: Required tap integrity authority\n",
            "    needs:\n      - pinned-policy\n      - current-upstream-canary\n",
            "    if: ${{ always() }}\n",
            "      PINNED_POLICY_RESULT: ${{ needs.pinned-policy.result }}\n",
            "      CANARY_RESULT: ${{ needs.current-upstream-canary.result }}\n",
            '          test "$PINNED_POLICY_RESULT" = success\n',
            '              test "$CANARY_RESULT" = skipped\n',
            '              test "$CANARY_RESULT" = success\n',
            '              test "$REF_PROTECTED" = true\n',
            "            schedule|workflow_dispatch)\n",
        )
        for marker in required_markers:
            expected_count = (
                2
                if marker
                in {
                    '              test "$CANARY_RESULT" = skipped\n',
                    '              test "$REF_PROTECTED" = true\n',
                }
                else 1
            )
            require(
                text.count(marker) == expected_count,
                f"{relative} terminal authority marker drifted: {marker.strip()}",
            )
        require(
            "AxiomLayer/" not in text,
            f"{relative} contains a noncanonical machine owner",
        )
        require(
            text.count("AXIOMLAYER_INPUT_CLASS: fabricated-public-metadata") == 1,
            f"{relative} fabricated input classification drifted",
        )
        require(
            text.count('test "$AXIOMLAYER_INPUT_CLASS" = fabricated-public-metadata')
            == 3,
            f"{relative} fabricated input runtime guards drifted",
        )
        require(
            text.count('test "$RUNNER_ENVIRONMENT" = github-hosted') == 3,
            f"{relative} hosted-runner runtime guards drifted",
        )
        require(
            text.count("export GIT_CONFIG_NOSYSTEM=1") == 3
            and text.count("export GIT_CONFIG_GLOBAL=/dev/null") == 3
            and text.count("export GIT_TERMINAL_PROMPT=0") == 3
            and text.count("unset GIT_ASKPASS SSH_ASKPASS") == 3,
            f"{relative} anonymous Git environment drifted",
        )
        require(
            text.count("rev-parse FETCH_HEAD") == 3,
            f"{relative} fetched revision binding drifted",
        )
        require(
            text.count('--no-tags --filter=blob:none origin "$target_ref"') == 2
            and "--depth=256" not in text,
            f"{relative} policy checkout history fetch drifted",
        )
        require(
            "  pull_request:\n    branches:\n      - main\n" in text,
            f"{relative} pull-request trigger drifted",
        )
        require(
            "  push:\n    branches:\n      - main\n" in text,
            f"{relative} push trigger drifted",
        )
        require(
            re.search(r"(?m)^\s+inputs\s*:", text) is None,
            f"{relative} declares real workflow inputs",
        )
        require(
            text.count('    - cron: "17 11 * * *"') == 1,
            f"{relative} daily schedule drifted",
        )
        job_runners = re.findall(r"(?m)^    runs-on:\s*(.*?)\s*$", text)
        require(
            job_runners == EXPECTED_JOB_RUNNERS,
            f"{relative} hosted job runners drifted",
        )
        matrix_runners = re.findall(r"(?m)^            runner:\s*(.*?)\s*$", text)
        require(
            matrix_runners == EXPECTED_MATRIX_RUNNERS,
            f"{relative} hosted runner matrix drifted",
        )
        require(
            "self-hosted" not in text.lower(),
            f"{relative} selects a self-hosted runner",
        )
        require(
            "-latest" not in text.lower(), f"{relative} uses a floating runner image"
        )
        require(
            len(re.findall(r"^permissions:\s*\{\}\s*$", text, re.MULTILINE)) == 1,
            f"{relative} must grant the token no permissions",
        )
        require(
            re.search(r"^\s*['\"]?environment['\"]?\s*:", text, re.MULTILINE) is None,
            f"{relative} declares a GitHub environment",
        )
        folded_text = text.casefold()
        for fragment in forbidden_fragments:
            require(
                fragment.casefold() not in folded_text,
                f"{relative} contains forbidden capability {fragment!r}",
            )
        action_references = re.findall(
            r"^\s*(?:-\s*)?['\"]?uses['\"]?\s*:\s*['\"]?([^\s#'\"]+)",
            text,
            re.MULTILINE,
        )
        for reference in action_references:
            match = re.fullmatch(r"([^@]+)@([0-9a-f]{40})", reference)
            require(
                match is not None, f"active Action is not full-SHA pinned: {reference}"
            )
            require(
                workflow_policy["allowedActions"].get(match.group(1)) == match.group(2),
                f"Action is outside the empty allowlist: {reference}",
            )
        for capability_key in ("uses", "environment", "continue-on-error"):
            require(
                re.search(
                    rf"(?:^|[{{,\s-])['\"]?{re.escape(capability_key)}['\"]?\s*:",
                    text,
                    re.MULTILINE,
                )
                is None,
                f"{relative} declares forbidden capability key {capability_key!r}",
            )
        require(
            not action_references,
            f"active workflow must remain Action-free: {action_references}",
        )


def verify_workflows(repo: Path, policy: dict[str, Any]) -> None:
    verify_active_workflow(repo, policy)
    verify_archive(repo, policy)


def verify_normalized_formulae(repo: Path, policy: dict[str, Any]) -> None:
    """Bind each reviewed formula normalization to both source and installed tree."""

    pin = policy["fork"]["pinnedCommit"]
    for entry in policy["formulaAudit"]["normalizedSources"]:
        path = entry["path"]
        candidate = repo / path
        require_no_symlink_ancestry(repo, candidate, f"normalized formula {path}")
        require(
            candidate.is_file() and not candidate.is_symlink(),
            f"normalized formula is absent or unsafe: {path}",
        )
        data = candidate.read_bytes()
        require(
            sha256_bytes(data) == entry["sha256"]
            and git_blob_id(data) == entry["normalizedBlob"],
            f"normalized formula bytes drifted: {path}",
        )
        source_mode, source_type, source_blob = git_tree_entry(repo, pin, path)
        require(
            source_mode == "100644"
            and source_type == "blob"
            and source_blob == entry["upstreamBlob"],
            f"normalized formula upstream binding drifted: {path}",
        )
        current_mode, current_type, current_blob = git_tree_entry(repo, "HEAD", path)
        require(
            current_mode == "100644"
            and current_type == "blob"
            and current_blob == entry["normalizedBlob"],
            f"normalized formula committed binding drifted: {path}",
        )


def verify_verifier_identity(policy: dict[str, Any]) -> None:
    verifier = Path(__file__)
    require(
        verifier.is_file() and not verifier.is_symlink(),
        "verifier must be a regular non-symlink file",
    )
    require(
        sha256_bytes(verifier.read_bytes())
        == policy["workflowPolicy"]["verifierSha256"],
        "verifier digest drifted from the reviewed policy",
    )


def raw_cask_bytes(commit: str, path: str) -> bytes:
    require(HEX40.fullmatch(commit) is not None, "unsafe cask commit")
    require(
        re.fullmatch(r"Casks/[a-z0-9]/[A-Za-z0-9+_.@-]+\.rb", path) is not None,
        f"unsafe cask path: {path}",
    )
    url = f"https://raw.githubusercontent.com/Homebrew/homebrew-cask/{commit}/{path}"
    request = urllib.request.Request(
        url, headers={"User-Agent": "AxiomLayer-homebrew-tap-integrity/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            require(
                response.status == 200,
                f"raw cask source returned HTTP {response.status}: {path}",
            )
            data = response.read(524_289)
    except (OSError, urllib.error.HTTPError) as error:
        raise IntegrityViolation(
            f"cannot fetch pinned cask definition {path}: {error}"
        ) from error
    require(len(data) <= 524_288, f"cask definition is unexpectedly large: {path}")
    return data


def validate_cask_definition(
    data: bytes, definition: dict[str, Any], core_root: Path
) -> dict[str, Any]:
    name = definition["name"]
    require(
        sha256_bytes(data) == definition["sha256"],
        f"cask {name} source SHA-256 drifted",
    )
    require(git_blob_id(data) == definition["blob"], f"cask {name} Git blob drifted")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IntegrityViolation(f"cask {name} is not UTF-8") from error
    calls = ruby_dsl_calls(text, f"cask {name}")
    require(
        any(
            call["name"] == "cask" and call["block"] and call["strings"] == [name]
            for call in calls
        ),
        f"cask token mismatch for {name}",
    )
    require(
        source_url_calls(calls),
        f"cask {name} has no declared HTTPS source URL",
    )
    declared_values, no_check = declared_sha256_values(calls, f"cask {name}")
    if definition["allowNoCheck"]:
        require(
            no_check,
            f"deferred cask {name} no longer has the expected no-check marker; review for promotion",
        )
    else:
        require(not no_check, f"active cask {name} uses sha256 :no_check")
    declared = sorted(set(declared_values))
    require(
        len(declared) >= definition["minimumDeclaredSha256"],
        f"cask {name} has too few declared SHA-256 values",
    )

    formula_dependencies = sorted(
        set(declared_cask_dependencies(calls, "formula", f"cask {name}"))
    )
    for dependency in formula_dependencies:
        require(
            formula_path(core_root, dependency) is not None,
            f"cask {name} depends on missing core formula {dependency}",
        )
    return {
        "name": name,
        "disposition": definition["disposition"],
        "declaredSha256": len(declared),
        "noCheck": no_check,
        "formulaDependencies": formula_dependencies,
        "caskDependencies": sorted(
            set(declared_cask_dependencies(calls, "cask", f"cask {name}"))
        ),
        "rubySourceExecuted": False,
        "hooksInvoked": False,
    }


def verify_casks(core_root: Path, policy: dict[str, Any]) -> list[dict[str, Any]]:
    cask_policy = policy["caskAudit"]
    commit = cask_policy["commit"]
    trees = remote_commit_trees(
        "https://github.com/Homebrew/homebrew-cask.git", [commit]
    )
    require(trees[commit] == cask_policy["tree"], "pinned cask tree drifted")
    results = []
    for definition in cask_policy["definitions"]:
        data = raw_cask_bytes(commit, definition["path"])
        results.append(validate_cask_definition(data, definition, core_root))
    return results


def verify_file_anchor(
    repo: Path, path: str, anchor: dict[str, str], label: str
) -> bytes:
    lexical_candidate = repo / path
    require_no_symlink_ancestry(repo, lexical_candidate, f"{label}:{path}")
    candidate = lexical_candidate.resolve(strict=True)
    require(
        candidate.is_relative_to(repo.resolve()),
        f"{label} path escapes repository: {path}",
    )
    require(candidate.is_file(), f"{label} file is absent: {path}")
    data = candidate.read_bytes()
    require(
        sha256_bytes(data) == anchor["sha256"], f"{label} file SHA-256 drifted: {path}"
    )
    require(git_blob_id(data) == anchor["blob"], f"{label} file blob drifted: {path}")
    tree_mode, tree_type, tree_blob = git_tree_entry(repo, "HEAD", path)
    require(
        tree_mode in {"100644", "100755"}
        and tree_type == "blob"
        and tree_blob == anchor["blob"],
        f"{label} committed blob drifted: {path}",
    )
    return data


def verify_consumer_repo(
    repo: Path, snapshot: dict[str, Any], label: str
) -> dict[str, bytes]:
    repo = repo.resolve()
    require(
        git_output(repo, "rev-parse", "HEAD") == snapshot["commit"],
        f"{label} HEAD does not equal policy commit",
    )
    require(
        git_output(repo, "rev-parse", "HEAD^{tree}") == snapshot["tree"],
        f"{label} tree does not equal policy tree",
    )
    return {
        path: verify_file_anchor(repo, path, anchor, label)
        for path, anchor in snapshot["files"].items()
    }


def verify_consumers(
    dotfiles_root: Path, margay_root: Path, policy: dict[str, Any]
) -> dict[str, Any]:
    consumers = policy["consumerSnapshots"]
    dotfiles_files = verify_consumer_repo(
        dotfiles_root, consumers["dotfiles"], "dotfiles"
    )
    margay_files = verify_consumer_repo(margay_root, consumers["margay"], "margay")

    brewfile = dotfiles_files["home/Brewfile"].decode("utf-8")
    selected_brews = re.findall(
        r'^\s*brew\s+["\']([^"\']+)["\']\s*$',
        strip_ruby_comments(brewfile),
        re.MULTILINE,
    )
    require(
        selected_brews == consumers["dotfiles"]["brewfileFormulaRoots"],
        "Brewfile formula roots drifted",
    )

    bootstrap = dotfiles_files["bin/bootstrap-box.sh"].decode("utf-8")
    for selection, witness in consumers["dotfiles"][
        "bootstrapSelectionWitnesses"
    ].items():
        require(
            witness in bootstrap, f"bootstrap source witness is absent for {selection}"
        )

    flake = margay_files["flake.nix"].decode("utf-8")
    core_pin = consumers["margay"]["homebrewCoreCommit"]
    cask_pin = consumers["margay"]["homebrewCaskCommit"]
    require(
        f'url = "github:Homebrew/homebrew-core/{core_pin}";' in flake,
        "Margay flake core pin drifted",
    )
    require(
        f'url = "github:Homebrew/homebrew-cask/{cask_pin}";' in flake,
        "Margay flake cask pin drifted",
    )

    device = json.loads(margay_files["config/device.json"])
    adapters = device.get("nativeAdapters") or {}
    active = sorted(
        item.get("name")
        for item in adapters.get("homebrewCasks", [])
        if isinstance(item, dict)
    )
    deferred = sorted(
        item.get("name")
        for item in adapters.get("deferredCasks", [])
        if isinstance(item, dict)
    )
    require(active == consumers["margay"]["activeCasks"], "Margay active casks drifted")
    require(
        deferred == consumers["margay"]["deferredCasks"],
        "Margay deferred casks drifted",
    )
    for item in adapters.get("homebrewCasks", []):
        require(
            item.get("checksumEnforcement") == "require_sha",
            f"active cask lacks require_sha: {item.get('name')}",
        )
    for item in adapters.get("deferredCasks", []):
        require(
            item.get("disposition") == "blocked",
            f"deferred cask is not blocked: {item.get('name')}",
        )

    return {
        "dotfilesCommit": consumers["dotfiles"]["commit"],
        "margayCommit": consumers["margay"]["commit"],
        "formulaRoots": policy["formulaAudit"]["roots"],
        "activeCasks": active,
        "deferredCasks": deferred,
    }


def verify_surface(
    policy: dict[str, Any], surface_id: str, expected_system: str, expected_machine: str
) -> dict[str, str]:
    surfaces = {surface["id"]: surface for surface in policy["canary"]["surfaces"]}
    require(surface_id in surfaces, f"unknown surface {surface_id}")
    surface = surfaces[surface_id]
    require(
        surface["unameSystem"] == expected_system,
        f"workflow/policy system disagreement for {surface_id}",
    )
    require(
        surface["unameMachine"] == expected_machine,
        f"workflow/policy architecture disagreement for {surface_id}",
    )
    actual_system = platform.system()
    actual_machine = platform.machine()
    require(
        actual_system == expected_system,
        f"runner system mismatch for {surface_id}: expected {expected_system}, got {actual_system}",
    )
    require(
        actual_machine == expected_machine,
        f"runner architecture mismatch for {surface_id}: expected {expected_machine}, got {actual_machine}",
    )
    return {"surface": surface_id, "system": actual_system, "machine": actual_machine}


def baseline(args: argparse.Namespace, policy: dict[str, Any]) -> dict[str, Any]:
    repo = args.repo.resolve()
    if args.skip_remote_fork:
        verify_pin_history(repo, policy)
    else:
        verify_remote_fork(repo, policy)
    verify_workflows(repo, policy)
    verify_normalized_formulae(repo, policy)
    formulae = audit_formula_closure(repo, policy["formulaAudit"]["roots"])
    casks = [] if args.skip_casks else verify_casks(repo, policy)
    return {
        "mode": "pinned-baseline",
        "commit": policy["fork"]["pinnedCommit"],
        "tree": policy["fork"]["pinnedTree"],
        "formulaAudit": formulae,
        "caskAudit": casks,
        "remoteForkVerified": not args.skip_remote_fork,
    }


def canary(args: argparse.Namespace, policy: dict[str, Any]) -> dict[str, Any]:
    repo = args.repo.resolve()
    state_before = repository_state(repo)
    require(not state_before["status"], "canary checkout is not clean")
    commit = validate_hex(args.commit, 160, "canary commit")
    actual = state_before["head"]
    require(
        actual == commit, f"canary checkout mismatch: expected {commit}, got {actual}"
    )
    tree = state_before["tree"]
    validate_hex(tree, 160, "canary tree")
    surface = verify_surface(
        policy, args.surface, args.expected_system, args.expected_machine
    )
    normalization_root = Path(__file__).parents[1].resolve()
    verify_normalized_formulae(normalization_root, policy)
    formula_audit = audit_formula_closure(
        repo,
        policy["formulaAudit"]["roots"],
        policy=policy,
        normalization_root=normalization_root,
    )
    representative_formulae = audit_representative_formulae(
        repo,
        policy["workflowPolicy"]["representativeFormulae"],
        policy=policy,
        normalization_root=normalization_root,
    )
    state_after = repository_state(repo)
    require(state_after == state_before, "metadata audit mutated the canary checkout")
    return {
        "mode": "current-upstream-canary",
        "commit": commit,
        "tree": tree,
        "automaticPromotion": False,
        "surface": surface,
        "formulaAudit": formula_audit,
        "metadataEvaluation": {
            "mode": "static-source-declarations",
            "formulae": representative_formulae,
            "rubySourceExecuted": False,
            "hooksInvoked": False,
            "repositoryStateUnchanged": True,
        },
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).with_name("tap-integrity-policy.json"),
        help="immutable integration policy",
    )
    commands = root.add_subparsers(dest="command", required=True)

    pinned = commands.add_parser(
        "baseline", help="verify the pinned fork and selected tap inputs"
    )
    pinned.add_argument("--repo", type=Path, required=True)
    pinned.add_argument(
        "--skip-remote-fork",
        action="store_true",
        help="unit-test escape hatch; CI must not use",
    )
    pinned.add_argument(
        "--skip-casks",
        action="store_true",
        help="unit-test escape hatch; CI must not use",
    )

    current = commands.add_parser(
        "canary", help="audit a detached current-upstream checkout"
    )
    current.add_argument("--repo", type=Path, required=True)
    current.add_argument("--commit", required=True)
    current.add_argument("--surface", required=True)
    current.add_argument("--expected-system", required=True)
    current.add_argument("--expected-machine", required=True)

    consumers = commands.add_parser(
        "consumers",
        help="verify private consumer snapshots locally without credentials",
    )
    consumers.add_argument("--dotfiles-root", type=Path, required=True)
    consumers.add_argument("--margay-root", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        policy = read_json(args.policy)
        validate_policy(policy)
        verify_verifier_identity(policy)
        if args.command == "baseline":
            result = baseline(args, policy)
        elif args.command == "canary":
            result = canary(args, policy)
        else:
            result = verify_consumers(args.dotfiles_root, args.margay_root, policy)
    except (IntegrityViolation, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"tap-integrity: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
