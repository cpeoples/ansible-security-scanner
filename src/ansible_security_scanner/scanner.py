#!/usr/bin/env python3
"""
Main Ansible Security Scanner class
"""

import contextlib
import logging
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

from .file_scanner import DependencyCollector, FileScanner, FixProposer, ParsedFile, TaintTracker
from .models import ScanReport, SecurityScore
from .patterns_manager import known_rule_ids, resolve_rule_specs
from .score_calculator import ScoreCalculator

logger = logging.getLogger(__name__)


# Ansible playbooks frequently use ``!vault`` and ``!unsafe`` tags that
# ``yaml.safe_load`` rejects, which would silently skip every structural
# check on the file. This loader treats any unknown ``!`` tag as an
# opaque string so the rest of the playbook still parses.
class _AnsibleTagTolerantLoader(yaml.SafeLoader):
    """SafeLoader that ignores unknown ``!xxx`` YAML tags.

    Extends ``yaml.SafeLoader``: any tag not otherwise registered is
    constructed as if it were the untagged scalar/sequence/mapping body.
    Used only for our internal parsing pass; we do NOT round-trip the data.
    """


def _construct_untagged(loader, tag_suffix, node):  # noqa: D401 - yaml API shape
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


_AnsibleTagTolerantLoader.add_multi_constructor("!", _construct_untagged)


class AnsibleSecurityScanner:
    """Main scanner class for Ansible playbook security analysis"""

    def __init__(
        self,
        directory: str = ".",
        target_files: Optional[list[str]] = None,
        allowlist_path: Optional[str] = None,
        show_suppressed: bool = False,
        *,
        disable_suppressions: bool = False,
        fail_on_suppressed: bool = False,
        max_suppressions: Optional[int] = None,
        fix_mode: bool = False,
        scan_git_history: bool = False,
        git_history_max_commits: int = 50,
        jobs: int = 1,
        dedup_cross_file: bool = False,
        select_rules: Optional[Iterable[str]] = None,
        ignore_rules: Optional[Iterable[str]] = None,
    ):
        """
        Initialize the scanner

        Args:
            directory: Directory to scan (default: current directory)
            target_files: Specific files to scan (if None, scans all .yml files in directory)
            allowlist_path: Path to allowlist YAML config (if None, uses default location)
            show_suppressed: If True, include findings suppressed by inline
                # nosec / # noqa directives in the report. If False (default),
                suppressed findings are dropped before scoring so CI noise
                stays low while audits can still opt in to see them.
            disable_suppressions: If True, every `# nosec` / `# noqa` directive
                in the scanned tree is ignored; the scanner behaves as if
                there were no suppressions at all. Used by release-gate runs
                where authors are not allowed to silence findings.
            fail_on_suppressed: If True, the scanner reports a non-zero exit
                condition (via ``ScanReport.suppressed_gate_failed``) when any
                finding was suppressed in the tree. CI-friendly strict mode.
            max_suppressions: If set, the scanner flags the run as failed if
                more than this many findings were suppressed across the tree.
            jobs: Number of worker threads for the per-file scan pass. Defaults
                to 1 (sequential) so runs are deterministic and identical to
                the pre-parallelism behaviour. Set higher (e.g. 4-8) to trade
                determinism of scan *order* for wall-clock time on large repos;
                the resulting findings set is still sorted downstream so the
                final report is bit-for-bit equivalent.
            dedup_cross_file: If True, findings that share
                ``(rule_id, canonicalized-code-snippet)`` across multiple files
                are collapsed to a single representative finding, with every
                other affected ``(file_path, line_number)`` preserved in the
                representative's ``duplicates`` list. Designed for repos with
                many near-identical variant playbooks (e.g. fork families) where
                the same task text repeats N times and inflates the report. Off
                by default so existing consumers get the per-location shape.
        """
        self.directory = Path(directory)
        self.target_files = target_files

        _allowlist_path = Path(allowlist_path) if allowlist_path else None

        # Resolve --select / --ignore once at construction time so any
        # typo (unknown rule_id) surfaces immediately rather than after
        # the scan starts. ``active_rule_ids = None`` means "no filter,
        # ship every rule" - the default. When set, the FileScanner
        # narrows its YAML pattern set AND the synthetic-finding gate
        # at the end of scan_file uses this same set.
        if select_rules is None and ignore_rules is None:
            active_rule_ids: Optional[frozenset[str]] = None
        else:
            universe = known_rule_ids()
            selected = (
                resolve_rule_specs(select_rules, universe) if select_rules is not None else universe
            )
            ignored = (
                resolve_rule_specs(ignore_rules, universe)
                if ignore_rules is not None
                else frozenset()
            )
            active_rule_ids = selected - ignored
        self.active_rule_ids = active_rule_ids

        self.file_scanner = FileScanner(
            self.directory,
            _allowlist_path,
            disable_suppressions=disable_suppressions,
            active_rule_ids=active_rule_ids,
        )
        self.score_calculator = ScoreCalculator()
        self.show_suppressed = show_suppressed
        self.disable_suppressions = disable_suppressions
        self.fail_on_suppressed = fail_on_suppressed
        self.max_suppressions = max_suppressions
        self.fix_mode = fix_mode
        self.scan_git_history = scan_git_history
        self.git_history_max_commits = git_history_max_commits
        # Clamp to at least 1 - 0 or negative would hang the executor.
        self.jobs = max(1, int(jobs))
        self.dedup_cross_file = dedup_cross_file

    def scan_directory(self) -> ScanReport:
        """Scan supported files in the specified directory or specific target files.

        File types scanned (in addition to ``*.yml``):
        - ``*.yaml`` - same semantics as .yml
        - ``*.j2``   - Jinja2 templates
        - ``*.cfg``  - ansible.cfg and similar INI-style configs
        Dot-prefixed files are excluded unless explicitly listed in ``target_files``.
        """
        findings = []
        scanned_files = 0

        supported_suffixes = {".yml", ".yaml", ".j2", ".cfg"}

        if self.target_files:
            logger.info("Scanning %d specified files", len(self.target_files))
            yml_files = []

            for target in self.target_files:
                # Accept both absolute paths and paths relative to self.directory
                # - --files and --changed-files can produce either.
                file_path = Path(target)
                if not file_path.exists():
                    file_path = self.directory / target

                if (
                    file_path.exists()
                    and file_path.suffix in supported_suffixes
                    and not file_path.name.startswith(".")
                ):
                    yml_files.append(file_path)
                    scanned_files += 1
                else:
                    if file_path.name.startswith("."):
                        logger.debug("Skipping dot file: %s", target)
                    else:
                        logger.warning(
                            "Skipping non-existent or unsupported file: %s (expected one of %s)",
                            target,
                            sorted(supported_suffixes),
                        )

            if not yml_files:
                logger.warning("No valid scannable files found in target files")
                return self._create_empty_report()
        else:
            logger.info("Scanning all supported files in directory: %s", self.directory)
            all_candidate_files: list[Path] = []
            for suffix in supported_suffixes:
                all_candidate_files.extend(self.directory.rglob(f"*{suffix}"))
            yml_files = [
                f for f in all_candidate_files if not f.name.startswith(".") and f.is_file()
            ]
            # Stable order for deterministic reporting.
            yml_files.sort()
            scanned_files = len(yml_files)

            if len(all_candidate_files) > len(yml_files):
                logger.info(
                    "Excluded %d dot files / non-regular files from scan",
                    len(all_candidate_files) - len(yml_files),
                )

            if not yml_files:
                logger.warning(
                    "No scannable files (%s) found in %s",
                    ", ".join(sorted(supported_suffixes)),
                    self.directory,
                )
                return self._create_empty_report()

        logger.info("Found %d file(s) to scan", len(yml_files))

        # Read+parse each file exactly once. The ParsedFile is then fed to
        # the per-file scanner, the TaintTracker, the DependencyCollector and
        # the cross-file sink pass below - previously each of those reopened
        # and re-parsed the same file, costing 3 disk reads + 2 yaml.safe_load
        # calls per file on large repos.
        #
        # When ``jobs`` > 1 the per-file scan stage runs in a ThreadPoolExecutor.
        # `scan_file` is pure with respect to the FileScanner instance (see
        # its docstring) so concurrent calls are safe; we sort the collected
        # findings afterwards to keep report output deterministic regardless
        # of completion order.
        total = len(yml_files)
        parsed_files: dict[Path, ParsedFile] = {}
        suppression_warnings: list = []

        def _read_and_parse(yml_file: Path) -> Optional[ParsedFile]:
            try:
                with open(yml_file, encoding="utf-8") as f:
                    raw = f.read()
            except OSError as e:
                logger.debug("Unable to read %s: %s", yml_file, e)
                return None
            except UnicodeDecodeError as e:
                logger.debug("Skipping non-UTF-8 file %s: %s", yml_file, e)
                return None
            try:
                data = yaml.safe_load(raw)
            except yaml.YAMLError as e:
                # Fall back to the Ansible-tolerant loader so playbooks
                # using !vault / !unsafe still yield structured data for
                # downstream AST-based checks (taint tracking, k8s spec
                # walker, credential hygiene). If even that fails, we keep
                # the existing "data=None" degraded path so line-based
                # scans still run.
                try:
                    data = yaml.load(raw, Loader=_AnsibleTagTolerantLoader)  # noqa: S506  (tolerant loader is SafeLoader + unknown-tag passthrough)
                except yaml.YAMLError:
                    logger.debug("YAML parse failed for %s: %s", yml_file, e)
                    data = None
            return ParsedFile(path=yml_file, content=raw, lines=raw.split("\n"), data=data)

        for idx, yml_file in enumerate(yml_files, 1):
            print(
                f"\r  Reading  [{idx}/{total}] {yml_file.name:<50s}",
                end="",
                flush=True,
                file=sys.stderr,
            )
            pf = _read_and_parse(yml_file)
            if pf is not None:
                parsed_files[yml_file] = pf

        if self.jobs > 1 and len(parsed_files) > 1:
            from concurrent.futures import ThreadPoolExecutor

            def _scan_one(item):
                yml_file, pf = item
                return yml_file, self.file_scanner.scan_file(yml_file, parsed=pf)

            results: dict[Path, tuple] = {}
            with ThreadPoolExecutor(max_workers=self.jobs) as pool:
                for done_idx, (yml_file, result) in enumerate(
                    pool.map(_scan_one, parsed_files.items()),
                    1,
                ):
                    print(
                        f"\r  Scanning [{done_idx}/{total}] {yml_file.name:<50s}",
                        end="",
                        flush=True,
                        file=sys.stderr,
                    )
                    results[yml_file] = result
            # Preserve the input file order when extending findings so that a
            # --jobs 1 run and a --jobs N run produce the same findings list
            # (per-file scan order is preserved; within a file, scan_file is
            # itself deterministic).
            for yml_file in parsed_files:
                file_findings, file_warnings = results[yml_file]
                findings.extend(file_findings)
                suppression_warnings.extend(file_warnings)
        else:
            for idx, (yml_file, pf) in enumerate(parsed_files.items(), 1):
                print(
                    f"\r  Scanning [{idx}/{total}] {yml_file.name:<50s}",
                    end="",
                    flush=True,
                    file=sys.stderr,
                )
                file_findings, file_warnings = self.file_scanner.scan_file(yml_file, parsed=pf)
                findings.extend(file_findings)
                suppression_warnings.extend(file_warnings)

        print(
            f"\r  Scanned {total} files, found {len(findings)} findings{' ' * 40}", file=sys.stderr
        )

        # Cross-file taint tracking: pass 1 collects tainted-variable
        # definitions (set_fact/register/include_vars); pass 2 scans every
        # sink (shell/command/uri/template/copy) and flags Jinja references
        # that resolve to a tainted name. Skipped when --select/--ignore
        # filters out ``cross_file_taint`` (the only rule it can emit).
        run_taint = self.active_rule_ids is None or "cross_file_taint" in self.active_rule_ids
        tracker = TaintTracker(Path(self.directory).resolve()) if run_taint else None
        dep_collector = DependencyCollector(Path(self.directory).resolve())
        for yml_file, pf in parsed_files.items():
            if pf.data is None:
                continue
            try:
                if tracker is not None:
                    tracker.collect_taints(yml_file, pf.data, pf.lines)
                dep_collector.collect(yml_file, pf.data, pf.content)
            except Exception as e:
                logger.debug("Taint/dep collection failed for %s: %s", yml_file, e)

        # Multi-hop propagation: a tainted variable passed through a chain
        # of set_fact assignments taints every downstream variable. Runs
        # once, after every file's direct taints have been recorded.
        if tracker is not None:
            try:
                tracker.propagate_transitive_taints()
            except Exception as e:
                logger.debug("Transitive taint propagation failed: %s", e)
            for yml_file, pf in parsed_files.items():
                if pf.data is None:
                    continue
                findings.extend(tracker.scan_sinks(yml_file, pf.data, pf.lines))

        # Opt-in git-history sweep: rescan every tracked file at each of
        # the last N commits that touched it, looking for secrets that
        # were later removed. Secrets once committed stay in git history
        # forever - a common class of real-world breach. This is off by
        # default because on a large repo it can add significant latency.
        if self.scan_git_history:
            findings.extend(self._scan_git_history(yml_files))

        # Dry-run fix proposer: when --fix is active, annotate each
        # finding with a unified-diff patch describing how to repair it.
        # The patch is NEVER written to disk; it only populates the
        # SecurityFinding.fix_patch field so the report (or SARIF output)
        # can display it. The CLI is responsible for extracting the
        # concatenated patch and either printing it to stdout or writing
        # it to --fix-output.
        if self.fix_mode:
            FixProposer().annotate(findings, Path(self.directory).resolve())

        # Partition findings by suppression state. Inline `# nosec` or similar
        # directives annotate a finding with ``suppressed_by``; by default we
        # drop those from the report (and from scoring) so CI noise stays low.
        # Auditors can pass ``--show-suppressed`` to see them in the report.
        suppressed_findings = [f for f in findings if f.suppressed_by]
        suppressed_count = len(suppressed_findings)
        if self.show_suppressed:
            active_findings = findings
        else:
            active_findings = [f for f in findings if not f.suppressed_by]
            if suppressed_count:
                logger.info(
                    "Inline suppression hid %d finding(s) (use --show-suppressed to view)",
                    suppressed_count,
                )
        findings = active_findings

        # Optional cross-file dedup: collapse findings that share
        # ``(rule_id, canonical-snippet)`` across multiple files into a
        # single representative finding (see ``_dedup_cross_file``). We
        # run this AFTER suppression partitioning so suppressed findings
        # never bleed into an active finding's ``duplicates`` list, and
        # BEFORE scoring so the security score reflects deduplicated
        # issue count rather than raw location count.
        if self.dedup_cross_file:
            from .file_scanner import _dedup_cross_file

            pre_count = len(findings)
            findings = _dedup_cross_file(findings)
            collapsed = pre_count - len(findings)
            if collapsed:
                logger.info(
                    "Cross-file dedup collapsed %d finding(s) "
                    "into their representative siblings (%d -> %d)",
                    collapsed,
                    pre_count,
                    len(findings),
                )

        # Collect suppression warnings (malformed directives). These are
        # always surfaced - a warning means the user *thought* they were
        # suppressing something but their directive was invalid.
        suppression_warning_lines = [
            f"WARN invalid suppression at {w.raw} -- {w.reason}" for w in suppression_warnings
        ]
        for line in suppression_warning_lines:
            logger.warning(line)

        # Compute suppression gate. If the caller asked to fail on any
        # suppression, or exceeded max_suppressions, we mark the report as
        # failed. The CLI uses this to set the process exit code.
        gate_failed = False
        if self.fail_on_suppressed and suppressed_count > 0:
            gate_failed = True
        if self.max_suppressions is not None and suppressed_count > self.max_suppressions:
            gate_failed = True

        security_score = self.score_calculator.calculate_security_score(findings, len(yml_files))

        summary = self._generate_summary(findings)

        scanned_file_paths = set()
        for yml_file in yml_files:
            relative_path = str(yml_file.relative_to(self.directory))
            scanned_file_paths.add(relative_path)

        # Files that scanned clean still get a per-file score; the score
        # calculator only emits entries for files that produced a finding.
        for file_path in scanned_file_paths:
            if file_path not in security_score.file_scores:
                security_score.file_scores[file_path] = 100

        scanned_file_names = [str(yml_file.relative_to(self.directory)) for yml_file in yml_files]

        return ScanReport(
            scan_timestamp=datetime.now().isoformat(),
            ansible_directory=str(self.directory),
            total_files_scanned=len(yml_files),
            scanned_file_names=scanned_file_names,
            findings=findings,
            security_score=security_score,
            summary=summary,
            suppressed_count=suppressed_count,
            suppression_warnings=suppression_warning_lines,
            suppressed_gate_failed=gate_failed,
            components=dep_collector.components,
        )

    def _scan_git_history(self, yml_files: list[Path]) -> list[Any]:
        """Opt-in pass that scans historical revisions of each tracked
        file for leaked secrets.

        Strategy:
        - For each file in ``yml_files``, call ``git log`` to get the last
          ``git_history_max_commits`` SHAs that touched it.
        - For each SHA, ``git show <sha>:<relpath>`` to pull the historical
          content into memory (NEVER write it back to disk).
        - Scan the content using the **same** line-pattern engine we use
          for live files, but narrowed to high-severity credential rules
          - history is noisy and we don't want to resurrect every old
          style-rule warning.
        - Emit findings with ``file_path`` as ``<rel>@<sha[:12]>`` so they
          partition cleanly from the live-file findings in reports.

        Gracefully skips when:
        - ``git`` is not on PATH
        - the working tree is not a git repo
        - ``git log``/``git show`` fails for any individual commit
        """
        findings: list[Any] = []
        if shutil.which("git") is None:
            logger.warning("--scan-git-history: git not found on PATH; skipping")
            return findings

        repo_root = Path(self.directory).resolve()
        # Verify it's a git repo.
        rc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
        if rc.returncode != 0:
            logger.warning(
                "--scan-git-history: %s is not a git working tree; skipping",
                repo_root,
            )
            return findings

        # Only keep credential-scanning rule IDs for history scanning.
        # History is noisy; a Jinja style warning on a 2-year-old commit
        # is not actionable, but a leaked AWS key is.
        from .patterns_manager import patterns_manager

        credential_patterns = [
            p
            for patterns in patterns_manager.loaded_patterns.values()
            for p in patterns
            if p.category == "hardcoded_credentials" and p.severity in ("CRITICAL", "HIGH")
        ]
        if self.active_rule_ids is not None:
            credential_patterns = [p for p in credential_patterns if p.id in self.active_rule_ids]
        if not credential_patterns:
            return findings

        max_c = self.git_history_max_commits

        for yml_file in yml_files:
            try:
                rel = yml_file.resolve().relative_to(repo_root)
            except ValueError:
                continue
            log_proc = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo_root),
                    "log",
                    f"-{max_c}",
                    "--pretty=%H",
                    "--",
                    str(rel),
                ],
                capture_output=True,
                text=True,
            )
            if log_proc.returncode != 0:
                continue
            shas = [s.strip() for s in log_proc.stdout.splitlines() if s.strip()]
            if len(shas) <= 1:
                # Only the live version - nothing to compare against.
                continue
            for sha in shas[1:]:  # skip HEAD (live version already scanned)
                show_proc = subprocess.run(
                    ["git", "-C", str(repo_root), "show", f"{sha}:{rel}"],
                    capture_output=True,
                    text=True,
                )
                if show_proc.returncode != 0:
                    continue
                historic = show_proc.stdout
                if not historic:
                    continue
                # Reuse FileScanner by writing historic content to a temp
                # file and running the normal scan_file path - no duplicate
                # engine logic, and all rule-dispatch/remediation glue
                # works unchanged.
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=yml_file.suffix,
                    delete=False,
                    encoding="utf-8",
                ) as tf:
                    tf.write(historic)
                    tf_path = Path(tf.name)
                try:
                    # Run the full scan on the synthesised historic file and
                    # filter to credential findings downstream. Re-running the
                    # full engine keeps rule-dispatch / remediation / dedup
                    # identical to live scans. We ignore the suppression-
                    # warnings half of the tuple: historic scans are synthetic
                    # temp files, not a place where `# nosec` directives
                    # should be surfaced.
                    historic_findings, _ = self.file_scanner.scan_file(tf_path)
                except Exception as e:  # pragma: no cover
                    logger.debug("history scan failed for %s@%s: %s", rel, sha, e)
                    historic_findings = []
                finally:
                    with contextlib.suppress(OSError):
                        tf_path.unlink()
                for f in historic_findings:
                    if f.rule_id not in {p.id for p in credential_patterns}:
                        continue
                    # Stamp the file_path with @sha so reports partition
                    # historical findings from live ones.
                    f.file_path = f"{rel}@{sha[:12]}"
                    f.description = f"[git-history] In commit {sha[:12]}: {f.description}"
                    findings.append(f)
        return findings

    def _create_empty_report(self) -> ScanReport:
        """Create an empty scan report for when no files are found"""
        return ScanReport(
            scan_timestamp=datetime.now().isoformat(),
            ansible_directory=str(self.directory),
            total_files_scanned=0,
            scanned_file_names=[],
            security_score=SecurityScore(
                overall_score=100,
                risk_score=0,
                category_scores={},
                severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0},
                file_scores={},
                recommendations_count=0,
            ),
            summary={"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            findings=[],
            suppressed_count=0,
            suppression_warnings=[],
            suppressed_gate_failed=False,
        )

    def _generate_summary(self, findings: list[Any]) -> dict[str, int]:
        """Generate summary statistics from findings"""
        summary = {
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == "CRITICAL"]),
            "high": len([f for f in findings if f.severity == "HIGH"]),
            "medium": len([f for f in findings if f.severity == "MEDIUM"]),
            "low": len([f for f in findings if f.severity == "LOW"]),
        }
        return summary
