# Agent Notes

Guidance for anyone (human or AI) picking this codebase up cold. See `PROJECT_PLAN.md`
for the architecture and design decisions, `STATUS.md` for what's actually done, and
`docs/REFERENCE_REPOSITORIES.md` for the licence-compliance audit behind the
clean-room decision.

## Hard constraints — do not relax these

- **`app/core/` imports no FastAPI, Starlette or Jinja2.** Enforced by
  `tests/unit/test_architecture.py::test_core_has_no_web_imports`. If a change needs
  a web-framework type inside `core`, the change belongs in `services/` instead.
- **No rule may key on country, region, language or nationality.** Enforced by
  `test_no_rule_mentions_country_or_nationality` and
  `test_country_never_contributes_to_score`.
- **Unavailable/disabled/unknown/errored threat intel is never evidence of
  cleanliness.** Enforced by `test_unavailable_intel_is_informational_only`.
- **No raw header content in a URL or query parameter, ever.** Enforced by
  `test_raw_header_never_appears_in_a_url_path_or_query_param`.
- **No fabricated threat-intelligence data**, in live mode or demo mode. Demo
  fixtures exist only for the four bundled samples' exact indicators
  (`app/demo_fixtures/fixtures.py`); anything else returns `DISABLED`, never an
  invented verdict.
- **No `Safe`/`Clean` verdict, no `BEC Confirmed` verdict.** These do not exist as
  values in `Verdict` (`app/core/models.py`) and should not be added.

## Before adding a dependency

Check its licence against the actual `LICENSE` file in its repository, not GitHub's
sidebar badge — two licence-misrepresentation traps were found during this project's
own reference audit (see `docs/REFERENCE_REPOSITORIES.md` §2, §3). This project is
MIT; no GPL or AGPL dependency may be added. `eml_parser` (AGPL-3.0) was specifically
evaluated and rejected for this reason — see `requirements.txt`'s header comment.

## Before touching `verify_spf` / `pyspf` usage

`pyspf` dispatches DNS through a module-level global (`spf.DNSLookup`), not an
instance method. `verify_spf` swaps that global under a lock for the duration of one
call. If you refactor this, re-run
`tests/unit/test_verification.py::test_spf_include_chain_resolves_through_injected_resolver_only`
under `pytest -W error::DeprecationWarning` — a regression here silently makes `pyspf`
reach the real internet, which the deprecation warning from `dns.resolver.query` is
what originally caught it during development.

## Before touching the connecting-IP selection in `analysis_service.py`

SPF must be evaluated against the IP the **first trusted receiver** observed
(`_spf_connecting_ip`), never the origin hop's IP. The origin hop of a
locally-injected message (a PGP gateway, a submission agent) legitimately has no
`from` clause and therefore no IP — using it silently breaks SPF verification for
exactly the header shape this tool is built to handle correctly. Regression test:
`test_spf_uses_trusted_receiver_ip_not_origin_hop_ip`.

## Test conventions

- Every test must run fully offline. DNS is mocked via `StaticResolver`
  (`app/core/verification/resolver.py`); HTTP is mocked via `respx`. If a test needs
  real network access or a real API key to pass, it's wrong.
- New correctness fixes should get a regression test named after the bug, with a
  docstring explaining what broke and why — see any test named
  `test_*_regression*` or with "Regression:" in its docstring for the pattern.
- Run `pytest -q -W error::DeprecationWarning` periodically, not just `pytest -q` — it
  has caught a real "silently reaching the network" bug once already (see above).

## Running the quality gate

```bash
ruff check .
pytest -q
pytest --cov=app --cov-report=term-missing
```

All three must be clean before considering a change complete. `pyproject.toml` sets
`fail_under = 80` for coverage.

## Samples

All four files in `samples/*.txt` are synthetic — RFC 2606 reserved domains, RFC 5737
documentation IP ranges. **Never add a real header to this repository**, including to
`samples/`. `samples/private/` is gitignored specifically so a real artifact can be
analysed locally without risk of it being committed.

If you add or change a sample, update its paired `*_expected.md` companion and the
fixtures in `app/demo_fixtures/fixtures.py` to match — they are keyed on the exact
indicator strings the sample contains, and `tests/integration/test_samples.py` asserts
specific scores and verdicts against the current sample content.
