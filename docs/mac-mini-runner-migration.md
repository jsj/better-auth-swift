# Migrating the Self-Hosted Runner from MacBook Pro to Mac Mini

## Current Setup (MBP)

- Runner installed at: `~/actions-runner`
- Runner name: `MacBook Pro`
- Labels: `self-hosted`, `macOS`, `ARM64`, `mac-ci`
- LaunchAgent: `~/Library/LaunchAgents/com.github.actions.better-auth-swift.runner.plist`
- Logs: `~/Library/Logs/github-actions-better-auth-swift-runner.log`
- Repo: `jsj/better-auth-swift`

## Step 1: Remove the MBP Runner

On the MacBook Pro:

```bash
# Stop the LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.github.actions.better-auth-swift.runner.plist

# Remove the runner registration from GitHub
cd ~/actions-runner
TOKEN=$(gh api -X POST repos/jsj/better-auth-swift/actions/runners/remove-token --jq .token)
./config.sh remove --token "$TOKEN"

# Optionally clean up
rm ~/Library/LaunchAgents/com.github.actions.better-auth-swift.runner.plist
rm -rf ~/actions-runner
```

## Step 2: Set Up the Mac Mini Runner

On the Mac Mini:

```bash
# Install the runner
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -L -o actions-runner-osx-arm64.tar.gz \
  "$(gh api repos/actions/runner/releases/latest \
    --jq '.assets[] | select(.name | test("osx-arm64")) | .browser_download_url')"
tar xzf actions-runner-osx-arm64.tar.gz

# Register with the SAME labels so no workflow changes are needed
TOKEN=$(gh api -X POST repos/jsj/better-auth-swift/actions/runners/registration-token --jq .token)
./config.sh --unattended \
  --url https://github.com/jsj/better-auth-swift \
  --token "$TOKEN" \
  --labels mac-ci \
  --name "mac-mini-ci" \
  --replace
```

## Step 3: Create a LaunchAgent on the Mac Mini

```bash
cat > ~/Library/LaunchAgents/com.github.actions.better-auth-swift.runner.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.github.actions.better-auth-swift.runner</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOUR_USER/actions-runner/run.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/YOUR_USER/actions-runner</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/YOUR_USER/Library/Logs/github-actions-better-auth-swift-runner.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOUR_USER/Library/Logs/github-actions-better-auth-swift-runner.error.log</string>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
EOF
```

Replace `YOUR_USER` with the Mac Mini username, then load:

```bash
launchctl load ~/Library/LaunchAgents/com.github.actions.better-auth-swift.runner.plist
```

## Step 4: Verify

```bash
# Check the runner is online from any machine with gh
gh api repos/jsj/better-auth-swift/actions/runners --jq '.runners[] | {name, status, labels: [.labels[].name]}'

# Trigger the smoke test
gh workflow run "Self Hosted Smoke" -R jsj/better-auth-swift
```

## Key Point

Because both runners use the `mac-ci` label, **no workflow file changes are needed**. The workflows already use:

```yaml
runs-on: [self-hosted, macOS, ARM64, mac-ci]
```

## Prerequisites for the Mac Mini

- macOS with Xcode installed (matching the version in workflows)
- `gh` CLI authenticated (`gh auth login`)
- Always-on power, no sleep: `sudo pmset -a sleep 0 disksleep 0 displaysleep 0 disablesleep 1`
