#!/usr/bin/env python3
"""Script to replace vendor blog URLs with neutral references."""

with open("src/db/attack_db.py", "r") as f:
    content = f.read()

replacements = {
    "https://www.stepsecurity.io/blog/tj-actions-changed-files-attack": "https://github.com/advisories/GHSA-mrrh-7r84-jfc8",
    "https://www.stepsecurity.io/blog/reviewdog-supply-chain-attack": "https://github.com/advisories/GHSA-qx2f-477c-35rq",
    "https://www.stepsecurity.io/blog/spotbugs-github-actions-supply-chain": "https://github.com/advisories/GHSA-qx2f-477c-35rq",
    "https://www.stepsecurity.io/blog/ultralytics-supply-chain-attack": "https://github.com/ultralytics/ultralytics/security/advisories",
    "https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection": "https://github.com/ultralytics/ultralytics/security",
    "https://www.stepsecurity.io/blog/kong-ingress-controller-attack": "https://github.com/Kong/kubernetes-ingress-controller/security",
    "https://socket.dev/blog/rspack-npm-token-theft": "https://github.com/web-infra-dev/rspack/security",
    "https://blog.gitguardian.com/codecov-supply-chain-breach/": "https://about.codecov.io/security-update/",
    "https://snyk.io/blog/open-source-npm-packages-colors-702-faker-6-6-6/": "https://github.com/advisories/GHSA-wjr3-rxjg-3jxc",
    "https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/": "https://nvd.nist.gov/vuln/detail/CVE-2022-23812",
    "https://socket.dev/blog/lottie-player-npm-supply-chain-attack": "https://github.com/LottieFiles/lottie-player/security",
    "https://www.stepsecurity.io/blog/pin-github-actions": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
    "https://www.legitsecurity.com/blog/github-actions-code-injection": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
    "https://www.legitsecurity.com/blog/artifact-poisoning-in-github-actions": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#potential-impact-of-a-compromised-runner",
    "https://socket.dev/blog/ctx-pypi-package-compromised": "https://www.cisa.gov/news-events/alerts",
    "https://blog.phylum.io/dozens-of-malicious-npm-packages-steal-credentials-data": "https://github.com/nicedoc/ua-parser-js/issues/536",
    "https://blog.phylum.io/pypi-malware-replaces-crypto-addresses-in-developers-clipboard/": "https://www.cisa.gov/news-events/alerts",
    "https://jfrog.com/blog/docker-hub-top-vulnerable-images/": "https://docs.docker.com/docker-hub/official_images/",
    "https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunspot": "https://nvd.nist.gov/vuln/detail/CVE-2020-10148",
    "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise": "https://nvd.nist.gov/vuln/detail/CVE-2023-29059",
    "https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-artifacts",
    "https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models/": "https://huggingface.co/docs/hub/security",
    "https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel": "https://github.com/advisories",
    "https://socket.dev/blog/npm-install-scripts-vuln": "https://docs.npmjs.com/cli/v10/using-npm/scripts#best-practices",
}

total = 0
for old, new in replacements.items():
    count = content.count(old)
    content = content.replace(old, new)
    total += count
    if count > 0:
        print(f"  Replaced {count}x: {old[:70]}...")

with open("src/db/attack_db.py", "w") as f:
    f.write(content)

print(f"\nDone. {total} vendor blog URLs replaced with neutral references.")
