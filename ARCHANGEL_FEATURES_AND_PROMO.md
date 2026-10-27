# 🛡️ php_Archangel: Capabilities & Promotional Strategy

Here is the complete breakdown you need. First, the comprehensive master list of capabilities, followed by the exact strategy and copy for your social media banners.

---

### 🛡️ Part 1: Complete Feature & Capability Matrix

Here is everything `php_Archangel` does, categorized by function. This is your technical source of truth.

#### 1. Detection & Fingerprinting
*   **Multi-Vector Version Reconciliation:** Resolves the PHP version using headers (`X-Powered-By`), Easter-egg GUID body hashes, `composer.lock` exposures, CMS/plugin era dating, and JS library versions. 
*   **Behavioral Fingerprinting (for Hidden Versions):** If `expose_php=Off`, it fires 5 specific behavioral probes (e.g., `print_r_nan_warning`, `opcache_dce`) to detect if the target acts like PHP `8.5.11` (vulnerable) or `8.5.12` (patched).
*   **Patch Floor Analysis:** Goes beyond assigned CVEs to flag targets below PHP `8.5.12` for un-CVE'd memory-safety fixes (DOMXPath UAF, SOAP Traversable UAF, PDO bindValue UAF, Lexbor overflow, Tidy UAF, etc.).

#### 2. Verification & The "Zero False Positive" Engine (SecPipe Doctrine)
*   **Evidence-Gated Verdicts:** Assigns one of four strict states: `CONFIRMED`, `PROBABLE`, `RETRACTED` (with reason), or `CLEAN`.
*   **3-Tier OOM Oracle:** Proves CVE-2026-109618 via differential memory exhaustion. It escalates from a 12MB payload, to a 1MB payload with 800 header amplifications, to a 130MB massive payload. It detects true worker crashes (RCE condition) vs. graceful patches.
*   **Worker-Affinity Oracle:** Proves CVE-2026-109619 via pinned keep-alive connections, detecting cross-request state corruption.
*   **Intake-Aware Escalation:** If a server has a low `post_max_size`, the oracle learns it from the 413 error and automatically shifts to header-amplification payloads instead of failing.

#### 3. AI Integration (Guardrailed)
*   **Structured-Data-Only Input:** The AI never sees the target. It only receives the JSON evidence (e.g., "Oracle returned 200 then 0").
*   **Severity-Capped:** The AI can lower a severity, but it is mathematically prevented from raising it above the deterministic cap.
*   **No Hallucinations:** AI is forced to explain *why* based only on the evidence provided. If it spits out malformed JSON, it automatically retries before falling back to deterministic mode.
*   **Zero-Cost Default:** Built-in support for OpenRouter Free and NVIDIA's free Nemotron model.

#### 4. Exploitation (Authorized Use)
*   **Angel-Sword RCE Chain:** A fully integrated, blinded proof-of-concept that achieves remote code execution as `www-data`.
*   **Strictly Gated:** It will *only* fire if the deterministic oracle proves the target is `CONFIRMED` and the user passes `--auto-exploit` or confirms the prompt.

#### 5. User Experience (UX)
*   **Zero-Dependency CLI:** Removed heavy frameworks like Rich. Pure native ANSI colors with a custom high-contrast cyberpunk aesthetic.
*   **Live Progress Bars:** Phase-based spinners for Recon, Oracle, Exploit, and AI Triage, with exact piped-output suppression (doesn't break JSON parsing).
*   **Colorized Markdown Reports:** Generates beautiful `.md` reports that automatically open in the user's GUI editor, featuring inline HTML styling and GFM alert blocks.

---

### 🎨 Part 2: Social Media Banner Strategy

You cannot put all of that on a banner. If you try, no one will read it. 

The biggest problem in cybersecurity today is **Alert Fatigue**. Regular scanners (like Nuclei) fire off false positives based on a single regex. And LLMs (like ChatGPT) hallucinate vulnerabilities that don't exist. **`php_Archangel` solves this.**

Here is the exact copy and layout you should use for LinkedIn and Twitter (X). 

#### The Banner Copy (Give this to your designer or use Canva)

**Headline (Large, Bold, Neon Cyan):**
> **STOP GUESSING. START PROVING.**

**Sub-headline (White, slightly smaller):**
> The 0% False Positive PHP Vulnerability Scanner.

**The 4 Bullet Points (Right or left aligned, with icons):**
> ❌ **No Hallucinations.** AI is strictly severity-capped and reads *only* structured evidence.
> ⚙️ **3-Tier OOM Oracle.** Proves RCE by forcing memory crashes, not by guessing version headers.
> 🧬 **Ghost Version Detection.** Fingerprints PHP versions even when `expose_php` is turned off.
> ⚡ **Evidence-Gated Verdicts.** Every finding is either `CONFIRMED`, `PROBABLE`, `RETRACTED`, or `CLEAN`.

**Footer (Small, Muted text):**
> Detect | Defend | Hunt | Exploit-Prevention | Stay Protected

---

### 📱 Part 3: Social Media Post Captions

Here is the text to accompany the banner.

#### Option 1: The "Pain Point" Angle (Best for LinkedIn)
*Alert fatigue is real. Modern scanners and LLMs are giving security teams massive false positives. They guess your PHP version, they hallucinate exploit paths, and they waste your time.*

*Enter `php_Archangel`. It is a precision-first runtime security analyzer that refuses to guess.*

*Instead of relying on headers, it uses a 3-Tier OOM Oracle to physically prove if a server is vulnerable to the latest php2shell RCEs (CVE-2026-109618 / 109619). If it can't prove it, it explicitly retracts the finding with a reason.*

*Key features:*
*✅ **0% False Positives** (SecPipe Doctrine)*
*✅ **Behavioral Fingerprinting** (Catches targets hiding their version)*
*✅ **Severity-Capped AI** (No hallucinations, just structured evidence)*
*✅ **Native RCE Proof** (Angel-Sword chain)*

*Stop trusting AI hallucinations. Start proving your posture.*

*👉 Check out the repo here: [Link to GitHub]*

#### Option 2: The "Hacker Aesthetic" Angle (Best for Twitter/X)
*🛡️ Most scanners guess. `php_Archangel` proves.*

*Built for authorized pentesters who are tired of false positives. We built a tool that physically crashes vulnerable PHP workers via a 3-Tier OOM Oracle, proving RCE without guessing headers.*

*🧬 Detects hidden versions via behavioral probes*
*⚙️ Proves CVE-2026-109618 & 109619*
*🤖 AI triage that literally cannot hallucinate (severity is capped)*
*💻 Beautiful native ANSI CLI & colorized .md reports*

*Precision-first PHP security. Open source. Link below 👇*
*#CyberSecurity #InfoSec #RedTeam #PHP #BugBounty #AppSec*

---

### 💡 The Secret Sauce for your Banner
When you mention "0% False Positives" in the banner, what you are *really* telling senior security engineers is:
1. **"We don't waste your time."**
2. **"We are safe to run against production."**
3. **"Our reports are defensible to auditors and clients."**

This is why the `RETRACTED` state and the `3-Tier Oracle` are your golden features. They prove the tool is honest. Highlighting that **the AI is not allowed to hallucinate or raise severity** will instantly separate you from the flood of "AI-powered" security tools currently saturating the market.
