---
name: ssh-setup
author: devtools-org
description: Configure SSH keys for GitHub access
tags: [ssh, git, devtools]
requires_bins: [ssh-keygen]
---

# SSH Key Setup

Generate and configure SSH keys for GitHub.

## Steps

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub
```

Then add the public key to your GitHub account at
https://github.com/settings/keys

## Verify

```bash
ssh -T git@github.com
```
