---
name: release-notes
description: Draft release notes from the git history since the last tag, add them to CHANGELOG.md, and optionally publish a GitHub release. Use when the user is cutting a release.
allowed-tools: Read, Edit, Bash(git log:*), Bash(git describe:*), Bash(gh release create:*)
---

# Release notes

1. Find the previous tag with `git describe --tags --abbrev=0`.
2. Read the commits since then: `git log <tag>..HEAD --no-merges --pretty='%h %s'`.
3. Group them under **Added**, **Changed**, **Fixed**. Drop chores and merge noise.
   Write for someone upgrading, not for the person who made the commit.
4. Show the draft to the user and wait for edits.
5. Prepend the approved section to `CHANGELOG.md` under a heading with the new version
   and today's date.
6. Only if the user asks for it, publish with
   `gh release create <version> --notes-file <file>`. This is visible to everyone who
   can see the repository, so confirm the version number first.

<!-- TODO: support monorepos with per-package changelogs -->
