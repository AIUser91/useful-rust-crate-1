# CI workflows (ready to install)

The automation account that prepares changes in this repo authenticates as a
GitHub App **without the `workflows` permission**, so it cannot create or
update files under `.github/workflows/`. The two workflow definitions this
repository needs (spec.md §6, issue #12) are therefore kept here, ready to be
copied into place by an administrator:

```sh
cp docs/workflows/ci.yml   .github/workflows/ci.yml
cp docs/workflows/fuzz.yml .github/workflows/fuzz.yml
```

They are plain YAML and inert at this path; once moved, `ci.yml` runs on every
push to `master` and every PR, and `fuzz.yml` builds the fuzz target per PR
plus a timed nightly run. Keep both copies in sync when editing (or delete
this directory after installing the real ones).
