# Self-hosted macOS GitHub Actions runner

The release workflow (`release-macos.yml`) defaults to `runs-on: self-hosted`.
This document explains how to set up and start the runner on your Mac.

## First-time setup

1. Go to the repo on GitHub →
   **Settings → Actions → Runners → New self-hosted runner**
2. Select **macOS / arm64**
3. GitHub shows you a download URL and a one-time token — copy the exact
   commands it gives you.  They look like this:

   ```bash
   mkdir ~/actions-runner && cd ~/actions-runner
   curl -o actions-runner-osx-arm64.tar.gz -L <URL_FROM_GITHUB>
   tar xzf actions-runner-osx-arm64.tar.gz
   ./config.sh --url https://github.com/mabels/project-43 --token <TOKEN>
   ```

4. When `config.sh` prompts you:
   - **Runner group** — press Enter (default)
   - **Runner name** — anything you like, e.g. `mac-mini`
   - **Labels** — press Enter to accept the defaults (`self-hosted,macOS,ARM64`)
   - **Work folder** — press Enter (`_work`)

The token expires within ~1 hour, so complete the config step promptly.
You only need to do this once; the runner is now registered with GitHub.

## Starting the runner (manual)

The runner is intentionally **not** installed as a launchd service.
Start it by hand whenever you want to accept a build:

```bash
cd ~/actions-runner
./run.sh
```

The runner will print `Listening for Jobs` when it is ready.
Leave the terminal open while the build runs; press **Ctrl-C** to stop it.

## Triggering a release build

With the runner listening, go to:
**Actions → Release — macOS → Run workflow**

The `runner` dropdown defaults to `self-hosted` — just click **Run workflow**.

Alternatively, pushing a `v*` tag triggers the workflow automatically
(the runner must already be listening at that point).

## If you want auto-start later

```bash
cd ~/actions-runner
./svc.sh install
./svc.sh start      # starts now and on every login
./svc.sh status     # check it is running
./svc.sh stop       # stop without uninstalling
./svc.sh uninstall  # remove the launchd service
```
