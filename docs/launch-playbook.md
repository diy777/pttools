# Launch Playbook

A two-week countdown for a public launch (HackerNews, ProductHunt, /r/netsec, security Twitter, LinkedIn). Adjust dates to your real launch.

## T-14: Foundation

- [ ] Trusted Publishing configured on PyPI (see `release-pypi.md`)
- [ ] LLM E2E smoke test green: `ANTHROPIC_API_KEY=... PTAI_E2E_LIVE=1 pytest tests/test_llm_e2e_smoke.py -v` (proves the live AI path works before recording the demo)
- [ ] Privacy Policy published at pentest-tools.local/privacy
- [ ] ToS published at pentest-tools.local/terms
- [ ] Status page live at status.pentest-tools.local with all monitors green for 7+ days
- [ ] At least one beta-customer testimonial (or screenshot of someone using it in the wild)
- [ ] Demo video recorded (60-90 sec, embedded on landing page above the fold)
- [ ] CHANGELOG up to date through latest release
- [ ] Tag latest release on GitHub with full notes

## T-10: Content

- [ ] Launch blog post drafted (1500-2500 words, your story + the technical bits)
- [ ] HackerNews post drafted (Show HN format: 1 sentence, link, technical detail in first comment)
- [ ] ProductHunt assets: 240x240 logo, 760x426 hero, 5+ screenshots, taglines
- [ ] /r/netsec submission drafted (technical-first, no marketing fluff)
- [ ] Twitter/X thread drafted (10-15 tweets, screenshots in tweets 2 and 5)
- [ ] LinkedIn long-form drafted (your audience leans toward CISOs)

## T-7: Pre-flight checks

- [ ] CLI installs cleanly from PyPI on Mac/Linux/Windows fresh VMs
- [ ] Dashboard signup → first scan → report flow takes under 5 minutes for a new customer
- [ ] Stripe checkout works for Pro and Team tiers
- [ ] Demo video plays correctly on all browsers including mobile Safari
- [ ] Email deliverability for transactional emails (verify with mail-tester.com)
- [ ] /api/cli/ingest endpoint handles 10x normal traffic in load test
- [ ] Backups: confirm last 24h of dashboard DB exists in offsite storage

## T-3: Coordinate

- [ ] Schedule HN post for Tuesday or Thursday, 8am Eastern (best engagement)
- [ ] Pre-warm: ask 3-5 trusted contacts to upvote/comment in first hour
- [ ] Notify any beta customers the launch is coming (so they don't get blindsided)
- [ ] DM 5-10 security influencers ahead of time with a personalized note + early access
- [ ] On-call rotation set: who's watching errors during launch day?
- [ ] Status page emergency contact verified

## T-1: Final

- [ ] Final version tag pushed
- [ ] PyPI release verified (`pip install pttools` on a fresh VM)
- [ ] Marketing site cache invalidated
- [ ] Status page header banner: "Launching tomorrow!"
- [ ] Sleep early. Eat well. Hydrate.

## Launch day

### Morning

- [ ] 8:00 ET: post HackerNews "Show HN: pentest-tools — autonomous pentests from one command"
- [ ] 8:00 ET: post ProductHunt
- [ ] 8:05 ET: post technical first-comment on HN
- [ ] 8:30 ET: post on Twitter/X with thread
- [ ] 9:00 ET: post on LinkedIn
- [ ] 9:30 ET: post on /r/netsec, /r/cybersecurity, /r/blueteamsec (link to blog post, not landing page; reddit allergic to marketing)

### Throughout the day

- [ ] Respond to every HN comment within 30 minutes for the first 6 hours
- [ ] Watch error monitor — any spike means rollback to T-1 build
- [ ] Watch signup conversion in dashboard — sub-10% from landing page is concerning, investigate copy
- [ ] Do not engage with hostile commenters; let community moderate
- [ ] Update status page if any incidents

### Evening

- [ ] Recap thread on Twitter (lessons from day one)
- [ ] Reply to any pending HN comments before bed
- [ ] Pre-write the 7-day retro post

## T+7: Retro

- [ ] Public retrospective post: signups, conversion rate, surprises, what's next
- [ ] Reach out to any signups who haven't completed their first scan with a personalized email
- [ ] Update marketing copy based on what HN/PH commenters consistently misunderstood
- [ ] Plan v0.11 based on the most-requested features from launch comments

## What can go wrong (and the fix)

| Risk | Mitigation |
|---|---|
| HN/PH front page → 50x traffic spike | Cloudflare in front of marketing; rate limit on signup form |
| Dashboard signups overload DB | Read replica + connection pooling configured ahead of time |
| Stripe webhook lag during signup spike | Async queue, idempotency keys |
| Negative HN comment about a real product flaw | Acknowledge it in the thread, link to the GH issue, ship the fix this week |
| Competitor sees the launch and copies a feature | Doesn't matter; speed of iteration is your moat |
| You forget to renew a domain mid-launch | Set auto-renew on every domain right now |

## After launch: what comes next

- Weekly "what's new in pentest-tools" newsletter (build the email list now)
- Monthly office hours / live demo session
- Open the GitHub Discussions tab; link to it from the README
- File a bug bounty program at HackerOne or Bugcrowd
- Start the SOC2 Type I audit clock (12-15 month process to Type II)
