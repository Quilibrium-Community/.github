# Adopting a project into the organization

Checklist for owners. This is the rare case, not the normal one. [CONTRIBUTING.md](CONTRIBUTING.md) is what outside contributors read, and it correctly tells them the answer is usually "not yet".

Only run this when there is already a working relationship with the author and a real reason to host the project. Nothing here is urgent: moving a repository in six months is exactly as easy as moving it today, and waiting costs nothing while moving too early costs a repository nobody maintains.

## Before anything moves

**Check the name is free.** If the org already has a repo with that name, or a fork in the same network, the transfer fails. Agree a rename first rather than after the author has done work.

**Get the licensing statement.** One line from the author, in writing, in the proposal issue: that they are the sole copyright holder, or that everyone else who contributed is fine with AGPL-3.0. If other people have merged pull requests under no clear license, adding a license file today does not cover their code retroactively. This is a paper trail, not a legal instrument, and it costs one sentence.

**Scan the full history for secrets:**

```bash
/d/scripts/scan-donated-repo.sh https://github.com/AUTHOR/THEIR-PROJECT
```

Start Docker Desktop first. Without it the script falls back to a narrow built-in scan and exits 2 (inconclusive) rather than pretending to be a pass.

A key committed once a year ago and deleted the next day is still in the history and still readable by anyone who clones. If the repo is public, treat every hit as already compromised: the author rotates the credential, and the project comes in as a single fresh commit with no history. Scrubbing history does not un-publish what was already out there.

**Read `.github/workflows/*.yml` by hand.** No scanner catches this. A workflow that ships secrets to an external endpoint contains no secret-shaped string, so it passes every automated check. Look for secret interpolation into `run:` steps, `pull_request_target` triggers, and third-party actions pinned to a mutable tag rather than a commit SHA.

**Re-run the scan immediately before the transfer completes.** The author still controls the repo in the gap between approval and handover, and can push in that window.

## Moving it

Only owners can create repositories in this org, and transferring into an org requires create permission, so **an outside collaborator cannot transfer a repo in themselves**. An owner has to be involved either way.

**Route A, the author hands it over.** They transfer to an owner's personal account, that owner transfers it into the org. Keeps issues, pull requests, stars, wiki, watchers, and all old links keep redirecting.

Watch for: the first hop needs the receiving owner to accept an emailed invitation, which expires after 24 hours. A repo that is a fork of a private upstream cannot be transferred this way at all. Complete the second hop promptly, since until you do, the project sits in a personal account rather than the org.

**Route B, we copy it in.** Mirror clone and mirror push into a fresh org repo. The author keeps their original and does nothing.

```bash
git clone --mirror https://github.com/AUTHOR/THEIR-PROJECT.git
cd THEIR-PROJECT.git
git push --mirror https://github.com/Quilibrium-Community/THEIR-PROJECT.git
```

Full commit history survives: every commit, branch, tag, author and date. Issues, pull requests, stars and old-link redirects do not. Ask the author to archive their original or point its README at the new home, otherwise two copies compete and people file bugs against the unwatched one.

Neither route carries **GHCR container images** (they stay in the author's namespace) or **GitHub Projects boards** (they belong to accounts, not repos).

## After the move

- Add the author as an **outside collaborator with Write** on that repo only. Not a member: the org's default member permission is `read` across all repos, which would expose the private website repo.
- **Verify the access level actually got set to Write.** GitHub adds the previous owner as a collaborator automatically, so it is easy to assume this is handled.
- The author needs **2FA enabled** or they cannot accept the invite. The org requires it. If they later disable it they are removed automatically.
- Turn on **branch protection** for `main`, and require review on changes to `.github/workflows/**` specifically. An outside collaborator with Write can otherwise edit a workflow that reads repo secrets.
- Turn on **secret scanning and push protection**. Free for public repos, and currently off by default across this org.
- Never add an org-wide shared secret to a newly adopted repo. Scope any CI credential to that repo alone.

## If a hosted project goes quiet

Archive it. Read-only, still public, clearly marked unmaintained. Do not delete work, and do not leave a dead project looking alive to someone who finds it through search.

*Last updated: 2026-08-28*
