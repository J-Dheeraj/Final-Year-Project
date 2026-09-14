"""compile_commands.json-driven preprocessing for stage 1.

Raw tree-sitter parsing sees source as literal text: a function generated
by a macro simply does not exist as a `function_definition` node. In the
Linux kernel that is not an edge case - it hides the syscall entry points,
which are exactly the attacker-controlled boundary reachcrs's whole
reachability premise is built on. `fs/open.c` parses to 37 functions raw;
after preprocessing it yields 138, the extra 101 being the real syscalls
(`__do_sys_open`, `__do_sys_openat2`, ...) that `SYSCALL_DEFINE*` expands
into. Preprocessing also resolves `#ifdef` branches against the build's
actual `.config` rather than guessing.

The flags matter: a kernel translation unit only preprocesses correctly
with its own include paths and `-D`s, which is what `compile_commands.json`
records. Generate one with the kernel's own tooling (no build required -
it reads the `.cmd` files a previous build already left behind):

    python scripts/clang-tools/gen_compile_commands.py -d . -o compile_commands.json

Two findings shape the design here, both measured rather than assumed:

1. **Parse the target file's lines, not the whole translation unit.**
   Fully expanded, `nft_payload.c` becomes 3.8MB / 99,696 lines of mostly
   kernel headers, and tree-sitter's C grammar fails on it outright - one
   ERROR node spanning lines 22 to 99,697, with lossy recovery that drops
   real functions. Keeping only the lines the linemarkers attribute to the
   target file gives a ~1,000-line unit that parses in 8ms. Type and struct
   declarations from headers are discarded with it, which costs nothing:
   finding function definitions is a syntactic question, not a semantic one.

2. **Preprocessing supplements raw parsing, it does not replace it.**
   Expanded kernel code carries GCC-specific constructs that tree-sitter
   parses worse than the original source (`nft_payload.c`: 30 functions raw
   vs. 26 preprocessed). So `reachability.py` unions the two, preferring the
   raw definition when both find a function - never worse than before, and
   substantially better wherever macros define functions.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

# GNU linemarker: `# <line> "<file>" [flags]` - emitted by cpp to say
# "the next output line came from <file> line <line>". Note `# 0 "..."`
# is valid here but is NOT valid C preprocessor syntax, which is why
# feeding raw `gcc -E` output straight to tree-sitter fails at line 1.
_LINEMARKER_RE = re.compile(r'^# (\d+) "([^"]*)"')

_PREPROCESS_TIMEOUT = 120.0


@dataclass(frozen=True)
class CompileCommand:
    """One entry from compile_commands.json."""

    file: str
    directory: str
    arguments: list[str]


@dataclass(frozen=True)
class PreprocessResult:
    """Outcome of preprocessing one file.

    `reason` exists so a failure is never silent: falling back to raw
    parsing produces exactly the "entry point not found in source" result
    this feature exists to fix, so a broken --compile-commands must not be
    indistinguishable from one that legitimately found nothing new.
    """

    source: str | None
    reason: str

    @property
    def ok(self) -> bool:
        return self.source is not None


def load_compile_commands(path: Path) -> dict[str, CompileCommand]:
    """Index a compile_commands.json by its `file` field.

    Accepts both shapes in the wild: `command` (a single string, what the
    kernel's gen_compile_commands.py emits) and `arguments` (a list, what
    clang tooling emits).
    """
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Generate one inside a configured kernel tree "
            f"with:\n  python scripts/clang-tools/gen_compile_commands.py "
            f"-d . -o compile_commands.json")

    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"{path} is not readable as JSON: {e}") from e
    if not isinstance(entries, list):
        raise ValueError(
            f"{path} must contain a JSON array of compile commands, "
            f"got {type(entries).__name__}")

    db: dict[str, CompileCommand] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        file = entry.get("file")
        if not file:
            continue
        arguments = entry.get("arguments")
        if arguments is None:
            arguments = shlex.split(entry.get("command", ""))
        if not arguments:
            continue
        db[file] = CompileCommand(file=file,
                                   directory=entry.get("directory", "."),
                                   arguments=list(arguments))
    return db


def preprocess_only_args(arguments: list[str]) -> list[str]:
    """Turn a compile command into a preprocess-only one.

    Drops `-c` and the object output, adds `-E`, and leaves every other
    flag (include paths, `-D`s, `-std=`, ...) exactly as the build system
    set it - guessing those is precisely what this module exists to avoid.
    """
    out: list[str] = []
    skip_next = False
    for arg in arguments:
        if skip_next:
            skip_next = False
            continue
        if arg == "-o":
            skip_next = True
            continue
        if arg.startswith("-o") and len(arg) > 2:
            continue
        if arg == "-c":
            continue
        out.append(arg)
    out.insert(1, "-E")
    return out


def reconstruct_target_source(preprocessed: str, target: str) -> str:
    """Rebuild just the target file's own code from `gcc -E` output.

    Walks the linemarkers to track which origin file each output line came
    from, keeps only those belonging to `target`, and places each one back
    at its original line number so reported line numbers stay meaningful
    (and stay comparable with a raw parse of the same file).

    Output lines following a marker normally map one-to-one onto successive
    source lines, and `origin_line` advances accordingly. When cpp instead
    emits several output lines that all belong to the *same* source line
    (it restates the marker to say so), they are joined with a space onto
    that one line rather than any being dropped - C is whitespace-
    insensitive, so this keeps the code syntactically intact without
    shifting any line number. Dropping them corrupts the file: an earlier
    draft kept only the first and silently broke the syntax of whatever
    function followed.
    """
    by_line: dict[int, list[str]] = {}
    origin_file: str | None = None
    origin_line = 0

    for raw_line in preprocessed.split("\n"):
        marker = _LINEMARKER_RE.match(raw_line)
        if marker:
            origin_line = int(marker.group(1))
            origin_file = marker.group(2)
            continue
        if origin_file is None:
            continue
        # `# 0 "file"` is a real linemarker form (cpp uses it for the initial
        # framing marker and for <built-in>/<command-line>), but there is no
        # line 0 in any file, and the reconstruction below starts at line 1 -
        # so anything landing there would be silently dropped. In practice cpp
        # always emits a further marker before real content; guard explicitly
        # rather than relying on that.
        if (origin_line >= 1 and _is_target(origin_file, target)
                and not raw_line.startswith("#")):
            by_line.setdefault(origin_line, []).append(raw_line)
        origin_line += 1

    if not by_line:
        return ""

    last = max(by_line)
    return "\n".join(" ".join(by_line.get(n, [])) for n in range(1, last + 1))


def _is_target(origin_file: str, target: str) -> bool:
    """Linemarkers may spell the file relatively or absolutely depending on
    how the build invoked the compiler, so compare on a suffix basis."""
    if origin_file == target:
        return True
    return origin_file.endswith("/" + target) or target.endswith("/" + origin_file)


def find_command(db: dict[str, CompileCommand],
                  path: Path) -> CompileCommand | None:
    """Locate the compile command for a source file.

    compile_commands.json may record `file` relatively (kernel style) or
    absolutely (clang style), so resolve both sides against the entry's
    own `directory` before comparing.
    """
    try:
        wanted = path.resolve()
    except OSError:
        return None

    direct = db.get(str(path))
    if direct is not None:
        return direct

    for entry in db.values():
        candidate = Path(entry.file)
        if not candidate.is_absolute():
            candidate = Path(entry.directory) / candidate
        try:
            if candidate.resolve() == wanted:
                return entry
        except OSError:
            continue
    return None


def preprocess_source(cc: CompileCommand,
                       timeout: float = _PREPROCESS_TIMEOUT) -> PreprocessResult:
    """Preprocess one translation unit and return just the target file's
    expanded source, along with a reason when that isn't possible.

    Callers fall back to raw parsing rather than losing the file entirely,
    but they are expected to surface `reason` - see PreprocessResult.
    """
    args = preprocess_only_args(cc.arguments)
    try:
        proc = subprocess.run(args, cwd=cc.directory, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return PreprocessResult(None, f"preprocessor timed out after {timeout:.0f}s")
    except OSError as e:
        return PreprocessResult(None, f"could not run {args[0]!r} ({e.strerror or e})")
    except subprocess.SubprocessError as e:
        return PreprocessResult(None, f"preprocessor failed to start ({e})")

    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        first = detail[0] if detail else "no stderr"
        return PreprocessResult(
            None, f"preprocessor exited {proc.returncode}: {first}")

    source = reconstruct_target_source(proc.stdout, cc.file)
    if not source.strip():
        return PreprocessResult(
            None, "preprocessor output contained no lines attributed to this file")
    return PreprocessResult(source, "ok")
