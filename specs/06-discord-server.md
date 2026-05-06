# Spec 06: Discord community server

**Status:** deferred
**Effort:** 2 hours setup + ongoing moderation
**Revenue impact:** medium (community network effect, support deflection)

## Goal

Public Discord server for the pentest-tools community. Reduces issue
churn on GitHub (some questions are conversations, not bug reports).
Serves as a network-effect engine: every #show-and-tell post draws
new users, every #cve-reports post is a credibility signal.

## Channel structure

### Welcome
- `#welcome` — readonly, sets the tone, links to README + DISCLAIMER
- `#rules` — community rules (no unauthorized targeting, no support
  through DMs, etc.)
- `#announcements` — readonly, releases and major news

### Help and discussion
- `#install-help` — getting up and running
- `#scope-and-roe` — questions about scope, authorization, legality
- `#agents-discussion` — agent-specific questions, pattern advice
- `#tooling-discussion` — questions about underlying tools (nmap, nuclei, etc.)
- `#troubleshooting` — bug-adjacent issues that aren't yet GitHub issues

### Show and tell
- `#show-and-tell` — engagements you're proud of (no client data!)
- `#cve-reports` — CVEs found with pentest-tools (with vendor-confirmed
  disclosure timing)
- `#playbooks-shared` — community-contributed YAML playbooks
- `#benchmarks` — benchmark results across models and challenges

### Pro / Team / Enterprise (gated)
- `#pro-customers` — open to anyone with a Pro subscription
  (verified via Stripe webhook → Discord role)
- `#team-customers` — Team subscribers
- `#enterprise-customers` — Enterprise customers (private channels per
  account if requested)

### Internal
- `#announcements-staff` — pre-release coordination (private)
- `#mod-log` — bot logs (private)

## Moderation rules

1. **No unauthorized targeting.** Posting `pentest-tools` runs against
   third-party targets without claimed authorization is an instant 7-day
   timeout. Repeat offenders banned.
2. **No client data leaks.** Even successful engagement screenshots
   must redact target hostnames, employee names, IP addresses.
3. **No DMs for support.** All support happens in public channels so
   future users find the answers.
4. **No marketplace posts.** No "I'll do your pentest for $X" posts.
   This isn't an Upwork.
5. **No cracking / piracy.** No discussions of cracking subscriptions,
   pirated tools, or reverse-engineering license checks.
6. **English primary.** Other-language channels can spin up later if
   communities form, but `#help` defaults to English.

## Bots

- **Stripe-Discord-Sync** (already exists in pentestai-private/discord/
  discord-stripe-sync) — assigns Pro/Team/Enterprise roles based on
  active subscription
- **GitHub** webhook posting new releases to `#announcements`
- **Carl-bot or MEE6** for moderation (auto-mod against spam, log link
  enforcement)

## Setup steps

### Day 1: Server + roles + bots

1. Create the Discord server `pentest-tools`
2. Set up role hierarchy: @Owner > @Mod > @Pro > @Team > @Enterprise > @Member
3. Create channels per the structure above
4. Wire `discord-stripe-sync` worker to issue roles on subscription
   webhook events
5. Install Carl-bot for auto-mod
6. Install GitHub bot, subscribe to release events from
   github.com/pentest-tools/pentest-tools

### Day 2: Initial content + invite

1. Pin: README link, getting-started link, SECURITY.md link in #welcome
2. Pin: rules in #rules
3. Add invite link to:
   - pentest-tools README footer
   - pentest-tools-agents README footer
   - pentest-tools.local footer
   - INSTALL.md
4. Soft-launch announcement: post in r/cybersecurity, r/AskNetsec,
   r/HowToHack with a "we just opened a Discord for pentest-tools users,
   come say hi" tone

### Ongoing

- Weekly: post a discussion prompt in #show-and-tell
- Monthly: post benchmark updates in #benchmarks
- Per-release: link release notes in #announcements

## Validation

- Server has 50+ members within 30 days of launch
- 10+ posts in #show-and-tell within 60 days
- 1 CVE posted in #cve-reports within 90 days
- Bot role-assignment works on new Pro/Team signup (test with sandbox
  Stripe customer)

## Out of scope

- Voice channels (text first; voice later if community asks)
- Gaming channel / off-topic (focused server, no scope creep)
- Sales pitching in non-customer channels (sales conversations happen
  via sales@pentest-tools.local, not in Discord)

## How to resume

Paste this spec as the next-session prompt. Or just spin up the server
yourself — the channel structure here is the only thing you'd need a
spec for, and the Stripe-Discord-Sync worker already exists.
