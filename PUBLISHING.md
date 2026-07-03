# Publishing `sether` to PyPI

Step-by-step. The package name `sether` is **available on PyPI** (checked
2026-06-25). Everything below assumes you are in `raeven/sether-py/`.

There are two routes. **Route A (manual)** gets your first release out today with
an API token. **Route B (CI, recommended long-term)** publishes automatically on
a git tag with no stored secrets. Do Route A once to claim the name, then switch
to Route B.

---

## 0. Prerequisites (one-time)

1. A **PyPI account**: <https://pypi.org/account/register/> (enable 2FA).
2. A **TestPyPI account** (separate from PyPI): <https://test.pypi.org/account/register/>
   — used for a safe dry-run.
3. Local tools (already in your venv from building):
   ```bash
   python -m pip install --upgrade build twine
   ```

---

## 1. Pre-flight checks (always run these first)

```bash
# from raeven/sether-py
python -m pytest -q                 # expect: 76 passed
rm -rf dist build *.egg-info
python -m build                     # builds dist/sether-<ver>.tar.gz + .whl
python -m twine check dist/*        # expect: PASSED for both
```

If any of these fail, **stop** — do not publish. A version, once uploaded to
PyPI, can never be reused or truly deleted.

---

## 2. Route A — manual publish (first release)

### 2a. Dry-run on TestPyPI

Create a TestPyPI API token (Account settings → API tokens → scope "Entire
account" for the first upload), then:

```bash
python -m twine upload --repository testpypi dist/*
# Username: __token__
# Password: <paste the pypi-... token>
```

Verify it installs cleanly from TestPyPI in a throwaway venv:

```bash
python -m venv /tmp/sether-check && source /tmp/sether-check/bin/activate
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ sether
python -c "import sether; print(sether.__version__)"   # 0.1.0
deactivate
```

(The `--extra-index-url` lets pip pull `phonenumbers` from real PyPI since it is
not on TestPyPI.)

### 2b. Real publish to PyPI

Create a **PyPI** API token (scope "Entire account" for the first upload; after
the project exists, regenerate a token scoped to just `sether`):

```bash
python -m twine upload dist/*
# Username: __token__
# Password: <paste the pypi-... token>
```

Done. The package is live at <https://pypi.org/project/sether/>.

```bash
pip install sether
```

---

## 3. Route B — automated publish via GitHub Actions (recommended)

This uses **PyPI Trusted Publishing** (OIDC): GitHub authenticates to PyPI
directly, so there is no token to store or rotate. The workflow is already in
[.github/workflows/publish.yml](.github/workflows/publish.yml).

### 3a. Put the code in a GitHub repo

```bash
cd raeven/sether-py
git init && git add -A && git commit -m "Sether Python 0.1.0"
git branch -M main
git remote add origin git@github.com:raeven-co/sether-py.git   # create this repo first
git push -u origin main
```

(If you instead vendor it inside the existing `raeven-co/sether` monorepo, adjust
the repo/path values in step 3b accordingly.)

### 3b. Register the Trusted Publisher on PyPI

PyPI → your account → **Publishing** → "Add a pending publisher"
(or, after the project exists, the project's *Publishing* tab):

| Field | Value |
| --- | --- |
| PyPI Project Name | `sether` |
| Owner | `raeven-co` |
| Repository name | `sether-py` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

### 3c. Release by tagging

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `Publish` workflow builds, runs `twine check`, and uploads to PyPI
automatically. Watch it under the repo's **Actions** tab.

---

## 4. Cutting a new version (every future release)

1. Bump the version in **two** places (keep them identical):
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `src/sether/__init__.py` → `__version__ = "X.Y.Z"`
2. Add a dated entry to [CHANGELOG.md](CHANGELOG.md).
3. Run the **Pre-flight checks** (section 1).
4. Commit, then either upload manually (Route A) or tag `vX.Y.Z` and push
   (Route B).

Semantic versioning: patch = fixes, minor = back-compatible features, major =
breaking API change.

---

## 5. Verify the release

```bash
pip index versions sether          # lists published versions
pip install --upgrade sether
python -c "import sether; print(sether.__version__)"
```

Check the project page renders the README and the right links:
<https://pypi.org/project/sether/>.

---

## 6. Marketing site + docs (Vercel)

The Python package points at the same marketing site as the npm package:

- `Homepage` → <https://setherai.vercel.app>
- `Documentation` → <https://setherai.vercel.app/docs/python>

Those URLs are served by `raeven/sether-marketing` (Next.js on Vercel). The
Python docs page (`/docs/python`) and the homepage `pip install sether` mentions
were added in this change. To ship them:

```bash
cd raeven/sether-marketing
npm install            # if node_modules is absent
npm run build          # verify it compiles
```

Then deploy as you normally do (push to the branch Vercel auto-deploys, or
`vercel --prod`). Once live, `setherai.vercel.app/docs/python` is the canonical
docs URL referenced from PyPI.

---

## Safety notes

- **Irreversible:** a published version number is permanent. Use TestPyPI first.
- **Never commit tokens.** Route B stores none; Route A tokens stay in your
  keychain / terminal only.
- Keep `pyproject.toml` and `__init__.py` versions in lockstep — CI builds from
  `pyproject`, but users read `sether.__version__`.
