import httpx
import asyncio

from typing import List

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential
)

from rag.models import (
    KnowledgeDocument,
    SourceType
)


# ══════════════════════════════════════════════
# SOURCES
# ══════════════════════════════════════════════

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CISA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# NOTE:
# حالياً بنستخدم Static Lists للـ CWE و CAPEC
# لتقليل التعقيد والتكلفة في النسخة الأولى (MVP).
# يمكن استبدالهم بمصادر حقيقية لاحقاً.


# ══════════════════════════════════════════════
# NVD
# ══════════════════════════════════════════════

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=10)
)
async def load_nvd(
    limit: int = 2000
) -> List[KnowledgeDocument]:
    """
    Load latest CVEs from NVD.

    MVP Version:
    Fetch latest 2000 CVEs only.
    """

    docs: List[KnowledgeDocument] = []

    async with httpx.AsyncClient(timeout=30) as client:

        params = {
            "resultsPerPage": min(limit, 2000),
            "startIndex": 0
        }

        response = await client.get(
            NVD_URL,
            params=params
        )

        response.raise_for_status()

        data = response.json()

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get("id", "")

            descriptions = cve.get("descriptions", [])

            description = next(
                (
                    d["value"]
                    for d in descriptions
                    if d.get("lang") == "en"
                ),
                ""
            )

            metrics = cve.get("metrics", {})

            cvss_score = 0.0

            if "cvssMetricV31" in metrics:
                cvss_score = (
                    metrics["cvssMetricV31"][0]
                    ["cvssData"]["baseScore"]
                )

            elif "cvssMetricV30" in metrics:
                cvss_score = (
                    metrics["cvssMetricV30"][0]
                    ["cvssData"]["baseScore"]
                )

            elif "cvssMetricV2" in metrics:
                cvss_score = (
                    metrics["cvssMetricV2"][0]
                    ["cvssData"]["baseScore"]
                )

            weaknesses = cve.get("weaknesses", [])

            cwe_ids = [
                d["value"]
                for w in weaknesses
                for d in w.get("description", [])
                if d["value"].startswith("CWE-")
            ]

            if not description:
                continue

            docs.append(
                KnowledgeDocument(
                    id=f"nvd-{cve_id}",
                    source=SourceType.NVD,
                    text=(
                        f"CVE: {cve_id}\n"
                        f"Description: {description}\n"
                        f"CVSS Score: {cvss_score}\n"
                        f"Weaknesses: {', '.join(cwe_ids)}"
                    ),
                    metadata={
                        "source_id" : cve_id,
                        "cve_id"    : cve_id,
                        "cvss_score": cvss_score,
                        "cwe_ids"   : cwe_ids,
                    },
                )
            )

    print(f"✅ NVD: loaded {len(docs)} CVEs")

    return docs


# ══════════════════════════════════════════════
# CISA KEV
# ══════════════════════════════════════════════

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=10)
)
async def load_cisa_kev() -> List[KnowledgeDocument]:
    """
    Load Known Exploited Vulnerabilities from CISA KEV.

    MVP Version:
    Fetch all known exploited CVEs.
    """

    docs: List[KnowledgeDocument] = []

    async with httpx.AsyncClient(timeout=30) as client:

        response = await client.get(CISA_URL)

        response.raise_for_status()

        data = response.json()

        for vuln in data.get("vulnerabilities", []):

            cve_id     = vuln.get("cveID", "")
            vendor     = vuln.get("vendorProject", "")
            product    = vuln.get("product", "")
            desc       = vuln.get("shortDescription", "")
            date_added = vuln.get("dateAdded", "")
            ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

            if not cve_id:
                continue

            docs.append(
                KnowledgeDocument(
                    id=f"cisa-{cve_id}",
                    source=SourceType.CISA_KEV,
                    text=(
                        f"CISA KEV - Known Exploited: {cve_id}\n"
                        f"Vendor: {vendor} | Product: {product}\n"
                        f"Ransomware: {ransomware}\n"
                        f"Date Added: {date_added}\n"
                        f"Description: {desc}"
                    ),
                    metadata={
                        "source_id" : cve_id,
                        "cve_id"    : cve_id,
                        "vendor"    : vendor,
                        "product"   : product,
                        "ransomware": ransomware,
                        "date_added": date_added,
                    },
                )
            )

    print(f"✅ CISA KEV: loaded {len(docs)} known exploited CVEs")

    return docs


# ══════════════════════════════════════════════
# MITRE ATT&CK
# ══════════════════════════════════════════════

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=10)
)
async def load_mitre_attack() -> List[KnowledgeDocument]:
    """
    Load attack techniques from MITRE ATT&CK.

    MVP Version:
    Fetch enterprise attack patterns only.
    """

    docs: List[KnowledgeDocument] = []

    async with httpx.AsyncClient(timeout=60) as client:

        response = await client.get(MITRE_URL)

        response.raise_for_status()

        data = response.json()

        for obj in data.get("objects", []):

            if obj.get("type") != "attack-pattern":
                continue

            if obj.get("revoked", False):
                continue

            technique_id = ""

            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            if not technique_id:
                continue

            name        = obj.get("name", "")
            description = obj.get("description", "")[:500]
            tactics     = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
            ]
            platforms   = obj.get("x_mitre_platforms", [])

            if not description:
                continue

            docs.append(
                KnowledgeDocument(
                    id=f"mitre-{technique_id}",
                    source=SourceType.MITRE_ATTACK,
                    text=(
                        f"MITRE Technique: {technique_id} - {name}\n"
                        f"Tactics: {', '.join(tactics)}\n"
                        f"Platforms: {', '.join(platforms)}\n"
                        f"Description: {description}"
                    ),
                    metadata={
                        "source_id"   : technique_id,
                        "technique_id": technique_id,
                        "name"        : name,
                        "tactics"     : tactics,
                        "platforms"   : platforms,
                    },
                )
            )

    print(f"✅ MITRE ATT&CK: loaded {len(docs)} techniques")

    return docs


# ══════════════════════════════════════════════
# CWE — Static List (MVP)
# ══════════════════════════════════════════════

def load_cwe() -> List[KnowledgeDocument]:
    """
    Load CWE weakness definitions.

    MVP Version:
    Static list of most common web weaknesses.
    """

    cwe_list = [
        {"id": "CWE-79",  "name": "Cross-site Scripting (XSS)",                  "desc": "Improper neutralization of input during web page generation allowing script injection."},
        {"id": "CWE-89",  "name": "SQL Injection",                                "desc": "Improper neutralization of special elements in SQL commands allowing database manipulation."},
        {"id": "CWE-22",  "name": "Path Traversal",                               "desc": "Improper limitation of pathname allowing access to files outside the intended directory."},
        {"id": "CWE-78",  "name": "OS Command Injection",                         "desc": "Improper neutralization of special elements in OS commands allowing arbitrary command execution."},
        {"id": "CWE-94",  "name": "Code Injection",                               "desc": "Improper control of code generation allowing attackers to inject and execute malicious code."},
        {"id": "CWE-287", "name": "Improper Authentication",                      "desc": "Insufficient proof of identity allowing unauthorized access."},
        {"id": "CWE-306", "name": "Missing Authentication for Critical Function",  "desc": "No authentication for functionality requiring provable user identity."},
        {"id": "CWE-502", "name": "Deserialization of Untrusted Data",            "desc": "Application deserializes untrusted data without sufficient verification."},
        {"id": "CWE-798", "name": "Use of Hard-coded Credentials",                "desc": "Software contains hard-coded credentials such as passwords or cryptographic keys."},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information",            "desc": "Product exposes sensitive information to unauthorized actors."},
        {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)",           "desc": "Web server retrieves URLs from upstream without proper validation."},
        {"id": "CWE-611", "name": "XML External Entity (XXE) Injection",          "desc": "Software processes XML with external entities resolving to unintended documents."},
        {"id": "CWE-434", "name": "Unrestricted Upload of Dangerous File",        "desc": "Software allows upload of dangerous file types that can be automatically processed."},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)",            "desc": "Web application cannot verify if requests were intentionally provided by the user."},
        {"id": "CWE-862", "name": "Missing Authorization",                        "desc": "No authorization check when actor attempts to access a resource or perform an action."},
    ]

    docs = [
        KnowledgeDocument(
            id=f"cwe-{cwe['id']}",
            source=SourceType.CWE,
            text=(
                f"Weakness: {cwe['id']} - {cwe['name']}\n"
                f"Description: {cwe['desc']}"
            ),
            metadata={
                "source_id": cwe["id"],
                "cwe_id"   : cwe["id"],
                "name"     : cwe["name"],
            },
        )
        for cwe in cwe_list
    ]

    print(f"✅ CWE: loaded {len(docs)} weakness definitions")

    return docs


# ══════════════════════════════════════════════
# CAPEC — Static List (MVP)
# ══════════════════════════════════════════════

def load_capec() -> List[KnowledgeDocument]:
    """
    Load CAPEC attack patterns.

    MVP Version:
    Static list of most common web attack patterns.
    """

    capec_list = [
        {"id": "CAPEC-66",  "name": "SQL Injection",                "desc": "Attacker exploits insufficient input validation to inject SQL commands into database queries."},
        {"id": "CAPEC-86",  "name": "XSS via HTTP Request Headers",  "desc": "Attacker injects malicious scripts via HTTP headers reflected in web responses."},
        {"id": "CAPEC-17",  "name": "Using Malicious Files",         "desc": "Attacker uploads malicious files to exploit insufficient file type validation."},
        {"id": "CAPEC-60",  "name": "Reusing Session IDs",           "desc": "Attacker reuses valid session IDs to hijack authenticated user sessions."},
        {"id": "CAPEC-115", "name": "Authentication Bypass",         "desc": "Attacker bypasses authentication mechanisms to gain unauthorized access."},
        {"id": "CAPEC-62",  "name": "Cross-Site Request Forgery",    "desc": "Attacker tricks authenticated users into executing unwanted actions on web applications."},
        {"id": "CAPEC-126", "name": "Path Traversal",                "desc": "Attacker uses path traversal sequences to access files outside intended directory."},
        {"id": "CAPEC-664", "name": "Server-Side Request Forgery",   "desc": "Attacker induces server to make requests to unintended internal or external resources."},
        {"id": "CAPEC-198", "name": "XSS",                          "desc": "Attacker injects malicious scripts into web pages viewed by other users."},
        {"id": "CAPEC-242", "name": "Code Injection",                "desc": "Attacker injects malicious code that is executed by the application."},
    ]

    docs = [
        KnowledgeDocument(
            id=f"capec-{capec['id']}",
            source=SourceType.CAPEC,
            text=(
                f"Attack Pattern: {capec['id']} - {capec['name']}\n"
                f"Description: {capec['desc']}"
            ),
            metadata={
                "source_id": capec["id"],
                "capec_id" : capec["id"],
                "name"     : capec["name"],
            },
        )
        for capec in capec_list
    ]

    print(f"✅ CAPEC: loaded {len(docs)} attack patterns")

    return docs


# ══════════════════════════════════════════════
# MAIN — Load All Sources
# ══════════════════════════════════════════════

async def load_all() -> List[KnowledgeDocument]:
    """
    Load all knowledge sources.
    Async sources run in parallel for speed.
    """

    print("🔄 Loading all knowledge sources...")

    # Async sources — run in parallel
    nvd_docs, cisa_docs, mitre_docs = await asyncio.gather(
        load_nvd(limit=2000),
        load_cisa_kev(),
        load_mitre_attack(),
    )

    # Sync sources
    cwe_docs   = load_cwe()
    capec_docs = load_capec()

    all_docs = nvd_docs + cisa_docs + mitre_docs + cwe_docs + capec_docs

    print(f"✅ Total: {len(all_docs)} documents loaded")

    return all_docs
