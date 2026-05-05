# Releasing

This document describes how CI/CD and releases work in this repository.

## Workflow Overview

The repository currently uses three GitHub Actions workflows:

- `Tests E2E`
  - runs on pushes to `main`
  - runs on pull requests targeting `main` or `devel`
- `Build Doxygen Docs`
  - runs on every pushed tag
  - can also be started manually from the GitHub Actions UI
- `Deploy Release`
  - runs on every pushed tag matching `v*`
  - creates either a GitHub pre-release or a production GitHub release, depending on the tag format and the branch that contains the tagged commit

## Release Rules

The release workflow accepts two tag formats:

- Production release: `vMAJOR.MINOR.PATCH`
  - example: `v2.7.6`
  - the tagged commit must be reachable from `main`
- Release candidate: `vMAJOR.MINOR.PATCH-rcN`
  - example: `v2.7.6-rc1`
  - the tagged commit must be reachable from an `rc-*` branch

If a pushed tag starts with `v` but does not match one of the formats above, the release workflow fails.

## Creating a Release Candidate

1. Prepare and push the release candidate branch.
   - branch name format: `rc-*`
   - example: `rc-2.7.6`
2. Make sure the target commit is on that `rc-*` branch.
3. Create an RC tag on that commit.

```bash
git checkout rc-2.7.6
git pull
git tag v2.7.6-rc1
git push origin rc-2.7.6
git push origin v2.7.6-rc1
```

4. GitHub Actions runs `Deploy Release`.
5. The workflow creates or updates a GitHub pre-release for that tag.

## Creating a Production Release

1. Make sure the target commit is on `main`.
2. Create a stable release tag on that commit.

```bash
git checkout main
git pull
git tag v2.7.6
git push origin main
git push origin v2.7.6
```

3. GitHub Actions runs `Deploy Release`.
4. The workflow creates or updates a production GitHub release for that tag.

## Documentation Builds

The `Build Doxygen Docs` workflow runs automatically for every pushed tag. This means both RC tags and production tags produce a documentation artifact.

The same workflow also supports manual runs from the GitHub Actions UI. Manual runs require the workflow file to be present on the repository default branch.

## Safe Testing

The safest way to test the release pipeline in this repository is to test the RC path, not the production path.

Recommended approach:

1. create a temporary `rc-*` branch
2. push the workflow changes on that branch
3. create a disposable RC tag such as `v2.7.6-rc-testing`
4. push the tag and inspect the workflow run
5. delete the test tag after verification

Example:

```bash
git checkout -b rc-2.7.6-test
git push origin rc-2.7.6-test
git tag v2.7.6-rc99
git push origin v2.7.6-rc-testing
```

Cleanup:

```bash
git push origin :refs/tags/v2.7.6-rc-testing
git tag -d v2.7.6-rc-testing
```

Notes:

- Testing the production path in this repository creates a real GitHub release. Do that only when you actually intend to publish one.
- If you need to test production release behavior end to end without publishing a real release, use a fork or a separate sandbox repository.

## Updating Workflows

Workflow files live in `.github/workflows/`.

For event-driven workflows such as `push`, GitHub uses the workflow file from the ref that triggered the event. That allows branch-level testing for tag and push based automation.

For manually triggered workflows such as `workflow_dispatch`, GitHub requires the workflow file to exist on the default branch before it is available from the Actions UI.

## Troubleshooting

If a release workflow does not run or fails, check the following:

- the tag starts with `v`
- the tag format is correct:
  - `v1.2.3` for production
  - `v1.2.3-rc1` for release candidates
- the tagged commit is reachable from the expected branch
  - `main` for production
  - `rc-*` for release candidates
- the workflow file exists in `.github/workflows/` on the relevant ref
- no more than three tags were pushed at once
