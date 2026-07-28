# Security Policy

We take the security of our software seriously. If you believe you have found a security vulnerability in any of our repositories, we appreciate your help in disclosing it to us responsibly.

## Reporting a Vulnerability

**All vulnerabilities must be reported through GitHub's Private Vulnerability Reporting in the affected repository.**

To submit a report:

1. Navigate to the repository where you found the issue.
2. Open the **Security** tab.
3. Click **Report a vulnerability** and complete the advisory form.

**Please do not report vulnerabilities through public GitHub issues, pull requests, discussions, or any other public channel.** Public disclosure before a fix is available puts our users at risk. Reports submitted publicly may be closed without a detailed response.

If the affected repository does not have private vulnerability reporting enabled, or you are unsure which repository is affected, contact us at **[support@privmx.com]**.

## What to Include in a Report

The more detail you provide, the faster we can validate and address the issue. Where possible, please include:

- The affected repository, version, commit, or endpoint
- A description of the vulnerability and its potential impact
- Step-by-step reproduction instructions or a proof of concept
- Any relevant logs, screenshots, or request/response captures
- Your assessment of severity
- Whether the issue is publicly known or has been reported elsewhere

## Rules of Engagement

By participating in security research against our projects and systems, you agree to the following:

- **English only.** All reports and follow-up communication must be in English so that our whole team can review them without delay or translation loss.
- **No social engineering.** Do not target our employees, contractors, users, or customers through phishing, vishing, smishing, pretexting, physical intrusion, or any other form of social engineering.
- **Stop at the point of recognition of personal data.** If your testing gives you access to personal data, credentials, or other confidential information, stop immediately at the moment you recognize it. Do not access further records, download, retain, copy, or share the data. Report what happened right away and include only what is strictly necessary to demonstrate the issue.

We additionally ask that you:

- Only test against assets you are authorized to test, and only within the scope described below.
- Use test accounts and test data that you own wherever possible.
- Do not modify, corrupt, or delete data that does not belong to you.
- Do not use automated scanners that generate high volumes of traffic without contacting us first.
- Give us reasonable time to remediate before disclosing the issue to anyone else.

## Scope

**In scope:** source code, dependencies, and configuration in the public repositories of this organization.

**Out of scope:**

- Findings from automated tools without a demonstrated, exploitable impact
- Missing security headers, or best-practice recommendations with no proven exploitability
- Vulnerabilities in third-party services or dependencies that we do not control — please report those to the relevant maintainer or vendor
- Issues requiring physical access, a rooted or jailbroken device, or a fully compromised host
- Self-XSS, clickjacking on pages with no sensitive state-changing actions, and missing rate limits with no security impact
- Social engineering, DoS, and any other activity excluded by the rules of engagement above

If you are unsure whether something is in scope, report it and we will tell you.

## Safe Harbor

We consider security research conducted in good faith and in accordance with this policy to be authorized.

If you are unsure whether an action is permitted, ask us before you proceed.

## Disclosure

We follow a coordinated disclosure model. Once a fix is available, we publish a security advisory in the affected repository describing the issue, the affected versions, and the remediation. We ask that you refrain from public disclosure until the advisory is published or we have agreed on a timeline together.

We do not offer bounty, but once the vulnerability is fixed, the details will be published to credit the researcher who reported it.
