"""HDAR Discovery — crawl GitHub for repos with permissive licenses, low competition,
and combinable functionality. Find unlikely cross-domain pairings that an LLM or
human-with-LLM wouldn't naturally approximate.

Discovery criteria:
  1. License allows commercial use (MIT, Apache-2.0, BSD-2/3, ISC, Unlicense)
  2. Low competition (few forks, few contributors, not trending)
  3. Functionality not interesting alone for LLM, but valuable when combined
  4. No existing API endpoint (logic exists but isn't served)

Combination strategy:
  - Semantic distance: pair repos from unrelated domains
  - Complementarity: one repo's output feeds another's input
  - Novelty score: how unlikely is this pairing? (higher = more valuable)
  - An LLM would pair "trading bot" + "sentiment analysis" (obvious).
  - We pair "fishing log parser" + "satellite orbit calculator" (non-obvious).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import math
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional


# Licenses that allow commercial use
COMMERCIAL_LICENSES = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc", "unlicense",
    "cc0-1.0", "mpl-2.0",  # weak copyleft, still commercial-ok
    "0bsd",
}

# Domain keywords for semantic distance calculation
DOMAIN_KEYWORDS = {
    "finance": ["trading", "market", "stock", "crypto", "forex", "portfolio", "backtest", "order", "exchange"],
    "ml": ["model", "training", "inference", "neural", "transformer", "embedding", "dataset", "fine-tune"],
    "web": ["frontend", "react", "vue", "css", "html", "ui", "dashboard", "template"],
    "systems": ["kernel", "driver", "filesystem", "memory", "scheduler", "runtime", "compiler"],
    "science": ["physics", "chemistry", "biology", "genomics", "astronomy", "climate", "simulation"],
    "text": ["nlp", "parser", "tokenizer", "translation", "summarize", "ocr", "document"],
    "audio": ["speech", "music", "sound", "voice", "tts", "asr", "audio"],
    "vision": ["image", "video", "camera", "cv", "detection", "segmentation", "render"],
    "data": ["database", "etl", "pipeline", "warehouse", "stream", "kafka", "queue"],
    "security": ["crypto", "auth", "firewall", "audit", "vulnerability", "pentest"],
    "geo": ["map", "gps", "gis", "location", "spatial", "satellite", "orbit", "coordinate"],
    "bio": ["genomics", "protein", "dna", "sequence", "medical", "health", "clinical"],
    "agriculture": ["farm", "crop", "soil", "weather", "irrigation", "harvest", "fishing"],
    "hardware": ["arduino", "raspberry", "iot", "sensor", "embedded", "fpga", "pcb"],
    "games": ["game", "engine", "physics", "render", "shader", "level", "sprite"],
    "logistics": ["shipping", "route", "delivery", "supply", "warehouse", "inventory"],
    "education": ["learn", "course", "tutorial", "quiz", "flashcard", "study"],
    "music": ["midi", "synth", "score", "chord", "scale", "audio"],
    "legal": ["contract", "compliance", "regulation", "statute", "clause"],
}


@dataclass
class DiscoveredRepo:
    name: str
    full_name: str
    url: str
    description: str
    language: str
    license: str
    stars: int
    forks: int
    contributors: int
    issues: int
    has_api: bool  # does it expose an API endpoint?
    topics: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)  # matched domains
    competition_score: float = 0.0  # 0 = no competition, 1 = saturated
    combinability_score: float = 0.0  # 0 = useless alone, 1 = perfect combiner
    novelty_potential: float = 0.0  # 0 = obvious, 1 = highly novel combination potential
    clone_url: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RepoCombination:
    repo_a: DiscoveredRepo
    repo_b: DiscoveredRepo
    semantic_distance: float  # 0 = same domain, 1 = completely unrelated
    complementarity: float  # 0 = no synergy, 1 = perfect fit
    novelty_score: float  # 0 = obvious pairing, 1 = highly non-obvious
    combined_value: str  # human-readable description of what the combination enables
    api_surface: str  # what API endpoint the combination would expose
    reward_estimate: float  # estimated contribution reward for serving this

    def to_dict(self) -> dict:
        return {
            "repo_a": self.repo_a.to_dict(),
            "repo_b": self.repo_b.to_dict(),
            "semantic_distance": self.semantic_distance,
            "complementarity": self.complementarity,
            "novelty_score": self.novelty_score,
            "combined_value": self.combined_value,
            "api_surface": self.api_surface,
            "reward_estimate": self.reward_estimate,
        }


def crawl_github(query: str = "", limit: int = 50, gh_token: str = "") -> list[DiscoveredRepo]:
    """Crawl GitHub repos via gh CLI or API.

    Filters:
      - License allows commercial use
      - Low competition (forks < 50, contributors < 10)
      - Has functionality but no API endpoint
    """
    token = gh_token or os.environ.get("GH_TOKEN", "")
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token

    # Search for repos with permissive licenses, sorted by least recently updated
    # (low competition = not actively maintained by many people)
    if not query:
        query = "license:mit license:apache-2.0 license:bsd-3-clause stars:<50 forks:<10"

    cmd = [
        "gh", "search", "repos", query,
        "--limit", str(limit),
        "--json", "name,fullName,url,description,primaryLanguage,licenseInfo,stargazersCount,forkCount,repositoryTopics,url",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        if r.returncode != 0:
            return []
        repos_data = json.loads(r.stdout)
    except Exception:
        return []

    repos = []
    for rd in repos_data:
        license_info = rd.get("licenseInfo", {})
        license_key = (license_info.get("key") or "").lower()

        # Filter: commercial-use license
        if license_key not in COMMERCIAL_LICENSES:
            continue

        # Extract topics
        topics_raw = rd.get("repositoryTopics", [])
        topics = []
        if isinstance(topics_raw, list):
            for t in topics_raw:
                if isinstance(t, dict):
                    topics.append(t.get("name", ""))
                elif isinstance(t, str):
                    topics.append(t)

        desc = rd.get("description", "") or ""
        lang = rd.get("primaryLanguage", {})
        lang_name = lang.get("name", "") if isinstance(lang, dict) else str(lang)

        # Detect domains from description + topics + name
        text = f"{rd.get('name','')} {desc} {' '.join(topics)}".lower()
        matched_domains = []
        for domain, keywords in DOMAIN_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                matched_domains.append(domain)

        stars = rd.get("stargazersCount", 0) or 0
        forks = rd.get("forkCount", 0) or 0

        # Competition score: lower stars/forks = lower competition
        competition = min(1.0, (stars / 100.0 + forks / 20.0) / 2.0)

        # Combinability: repos with clear input/output interfaces but no API
        has_api = any(kw in text for kw in ["api", "endpoint", "server", "rest", "graphql", "fastapi", "flask"])
        # If it has an API, it's less interesting (already served)
        # If it has logic but no API, it's a combinability candidate
        has_logic = any(kw in text for kw in ["parser", "converter", "calculator", "analyzer", "processor", "engine", "tool", "cli", "library", "module"])
        combinability = 0.0
        if has_logic and not has_api:
            combinability = 0.8
        elif has_logic and has_api:
            combinability = 0.3
        elif not has_logic and not has_api:
            combinability = 0.1

        # Novelty potential: repos from unusual domains or with unusual topic combinations
        unusual_domains = {"agriculture", "geo", "bio", "legal", "music", "logistics", "education"}
        if any(d in unusual_domains for d in matched_domains):
            novelty_potential = 0.9
        elif len(matched_domains) >= 2:
            novelty_potential = 0.6  # cross-domain within one repo
        elif matched_domains:
            novelty_potential = 0.3
        else:
            novelty_potential = 0.1

        repo = DiscoveredRepo(
            name=rd.get("name", ""),
            full_name=rd.get("fullName", rd.get("name", "")),
            url=rd.get("url", ""),
            description=desc,
            language=lang_name,
            license=license_key,
            stars=stars,
            forks=forks,
            contributors=min(10, forks + 1),  # approximate
            issues=0,
            has_api=has_api,
            topics=topics,
            domains=matched_domains,
            competition_score=competition,
            combinability_score=combinability,
            novelty_potential=novelty_potential,
            clone_url=f"https://github.com/{rd.get('fullName', '')}.git",
        )
        repos.append(repo)

    return repos


def crawl_user_repos(username: str, limit: int = 100, gh_token: str = "") -> list[DiscoveredRepo]:
    """Crawl a specific user's repos — useful for finding combinable assets you already own."""
    token = gh_token or os.environ.get("GH_TOKEN", "")
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token

    cmd = [
        "gh", "repo", "list", username,
        "--limit", str(limit),
        "--json", "name,nameWithOwner,url,description,primaryLanguage,licenseInfo,stargazerCount,forkCount,repositoryTopics",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        if r.returncode != 0:
            return []
        repos_data = json.loads(r.stdout)
    except Exception:
        return []

    repos = []
    for rd in repos_data:
        license_info = rd.get("licenseInfo", {})
        license_key = (license_info.get("key") or "").lower()

        # For user repos, we don't filter by license as strictly
        # (they own it, so commercial use is implied)
        if not license_key:
            license_key = "proprietary-owned"

        topics_raw = rd.get("repositoryTopics", [])
        topics = []
        if isinstance(topics_raw, list):
            for t in topics_raw:
                if isinstance(t, dict):
                    topics.append(t.get("name", ""))
                elif isinstance(t, str):
                    topics.append(t)

        desc = rd.get("description", "") or ""
        lang = rd.get("primaryLanguage", {})
        lang_name = lang.get("name", "") if isinstance(lang, dict) else str(lang)

        text = f"{rd.get('name','')} {desc} {' '.join(topics)}".lower()
        matched_domains = []
        for domain, keywords in DOMAIN_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                matched_domains.append(domain)

        stars = rd.get("stargazerCount", 0) or 0
        forks = rd.get("forkCount", 0) or 0

        has_api = any(kw in text for kw in ["api", "endpoint", "server", "rest", "graphql", "fastapi", "flask", "space"])
        has_logic = any(kw in text for kw in ["parser", "converter", "calculator", "analyzer", "processor", "engine", "tool", "cli", "library", "module", "system", "agent", "optimizer"])
        combinability = 0.8 if (has_logic and not has_api) else (0.4 if has_logic else 0.1)

        unusual_domains = {"agriculture", "geo", "bio", "legal", "music", "logistics", "education"}
        novelty_potential = 0.9 if any(d in unusual_domains for d in matched_domains) else (0.5 if len(matched_domains) >= 2 else 0.2)

        repo = DiscoveredRepo(
            name=rd.get("name", ""),
            full_name=rd.get("nameWithOwner", rd.get("name", "")),
            url=rd.get("url", ""),
            description=desc,
            language=lang_name,
            license=license_key,
            stars=stars,
            forks=forks,
            contributors=min(10, forks + 1),
            issues=0,
            has_api=has_api,
            topics=topics,
            domains=matched_domains,
            competition_score=min(1.0, stars / 50.0),
            combinability_score=combinability,
            novelty_potential=novelty_potential,
            clone_url=f"https://github.com/{rd.get('nameWithOwner', '')}.git",
        )
        repos.append(repo)

    return repos


def semantic_distance(repo_a: DiscoveredRepo, repo_b: DiscoveredRepo) -> float:
    """Calculate semantic distance between two repos.

    0 = same domain, 1 = completely unrelated.
    Uses Jaccard distance on matched domains.
    """
    set_a = set(repo_a.domains)
    set_b = set(repo_b.domains)

    if not set_a and not set_b:
        return 0.5  # unknown → moderate distance

    intersection = set_a & set_b
    union = set_a | set_b

    jaccard_similarity = len(intersection) / len(union) if union else 0.0
    distance = 1.0 - jaccard_similarity

    # Boost distance if domains are from very different categories
    # (e.g., finance + agriculture is more distant than finance + ml)
    cross_category_boost = 0.0
    far_pairs = {
        frozenset({"finance", "agriculture"}),
        frozenset({"finance", "bio"}),
        frozenset({"finance", "music"}),
        frozenset({"ml", "agriculture"}),
        frozenset({"ml", "legal"}),
        frozenset({"systems", "bio"}),
        frozenset({"systems", "agriculture"}),
        frozenset({"geo", "bio"}),
        frozenset({"geo", "music"}),
        frozenset({"security", "agriculture"}),
        frozenset({"games", "bio"}),
        frozenset({"games", "legal"}),
        frozenset({"hardware", "legal"}),
        frozenset({"hardware", "music"}),
        frozenset({"logistics", "bio"}),
        frozenset({"education", "security"}),
    }
    for pair in far_pairs:
        if pair.issubset(set_a | set_b) and pair.issubset(set_a) ^ pair.issubset(set_b):
            cross_category_boost = 0.3
            break

    return min(1.0, distance + cross_category_boost)


def complementarity(repo_a: DiscoveredRepo, repo_b: DiscoveredRepo) -> float:
    """How well do the repos complement each other?

    High when:
      - One produces data, the other consumes it
      - One has logic, the other has interface
      - Neither has an API alone, but together they form one
    """
    score = 0.0

    # If neither has an API but both have logic → together they could form an API
    if not repo_a.has_api and not repo_b.has_api:
        score += 0.4

    # If one has API and other has logic → logic becomes endpoint
    if repo_a.has_api != repo_b.has_api:
        score += 0.3

    # Different languages → more complementary (different ecosystems)
    if repo_a.language and repo_b.language and repo_a.language != repo_b.language:
        score += 0.2

    # Different domains → cross-domain complement
    if repo_a.domains and repo_b.domains:
        if not set(repo_a.domains) & set(repo_b.domains):
            score += 0.3

    # High combinability on both → strong complement
    score += (repo_a.combinability_score + repo_b.combinability_score) / 2.0 * 0.3

    return min(1.0, score)


def describe_combination(repo_a: DiscoveredRepo, repo_b: DiscoveredRepo) -> tuple[str, str]:
    """Generate a human-readable description of what the combination enables,
    and what API surface it would expose.

    Returns (combined_value, api_surface).
    """
    domains_a = repo_a.domains or ["general"]
    domains_b = repo_b.domains or ["general"]

    # Build description from domains
    domain_a = domains_a[0]
    domain_b = domains_b[0]

    combined_value = (
        f"Combining {repo_a.name} ({domain_a}) with {repo_b.name} ({domain_b}) "
        f"creates a {domain_a}-{domain_b} pipeline: "
        f"{repo_a.name} processes {domain_a} inputs and feeds outputs to "
        f"{repo_b.name} which transforms them into {domain_b} outputs. "
        f"Neither repo alone provides this cross-domain capability."
    )

    # API surface: what endpoint would this combination serve?
    if not repo_a.has_api and not repo_b.has_api:
        api_surface = f"POST /api/{domain_a}-to-{domain_b} — accepts {domain_a} data, returns {domain_b} results"
    elif repo_a.has_api and not repo_b.has_api:
        api_surface = f"POST /api/{domain_b}/process — {repo_b.name}'s logic exposed via {repo_a.name}'s server"
    elif repo_b.has_api and not repo_a.has_api:
        api_surface = f"POST /api/{domain_a}/process — {repo_a.name}'s logic exposed via {repo_b.name}'s server"
    else:
        api_surface = f"POST /api/{domain_a}-{domain_b}/combined — both APIs unified into single endpoint"

    return combined_value, api_surface


def find_combinations(repos: list[DiscoveredRepo], top_n: int = 20) -> list[RepoCombination]:
    """Find the most novel, unlikely combinations from a set of discovered repos.

    Scoring:
      - High semantic distance (unrelated domains)
      - High complementarity (one feeds the other)
      - High novelty (non-obvious pairing)
      - Low competition on both repos
    """
    combinations = []

    for i, a in enumerate(repos):
        for b in repos[i + 1:]:
            # Skip if both have APIs and same domain (already served, obvious)
            if a.has_api and b.has_api and set(a.domains) & set(b.domains):
                continue

            dist = semantic_distance(a, b)
            comp = complementarity(a, b)

            # Novelty: high distance + high complementarity = unlikely but valuable
            novelty = (dist * 0.5 + comp * 0.3 + (a.novelty_potential + b.novelty_potential) / 2.0 * 0.2)

            # Skip low-novelty combinations
            if novelty < 0.3:
                continue

            combined_value, api_surface = describe_combination(a, b)

            # Reward estimate: based on novelty + complementarity + low competition
            low_comp_bonus = (1.0 - a.competition_score) * (1.0 - b.competition_score)
            reward = novelty * 0.5 + comp * 0.3 + low_comp_bonus * 0.2

            combo = RepoCombination(
                repo_a=a,
                repo_b=b,
                semantic_distance=dist,
                complementarity=comp,
                novelty_score=novelty,
                combined_value=combined_value,
                api_surface=api_surface,
                reward_estimate=reward,
            )
            combinations.append(combo)

    # Sort by novelty score (most unlikely first)
    combinations.sort(key=lambda c: c.novelty_score, reverse=True)
    return combinations[:top_n]


def score_repo_for_serving(repo: DiscoveredRepo) -> float:
    """Score how valuable it would be to serve this repo's logic as an API endpoint.

    High score = repo has logic but no API, low competition, high combinability.
    """
    if repo.has_api:
        return 0.1  # already served

    score = 0.0
    score += repo.combinability_score * 0.4
    score += (1.0 - repo.competition_score) * 0.3
    score += repo.novelty_potential * 0.3
    return score


def discover_and_combine(
    username: str = "",
    search_query: str = "",
    limit: int = 50,
    top_combinations: int = 20,
    gh_token: str = "",
) -> dict:
    """Full discovery pipeline: crawl → filter → score → combine → rank.

    Returns:
      {
        "repos": [DiscoveredRepo, ...],
        "combinations": [RepoCombination, ...],
        "serving_candidates": [DiscoveredRepo, ...],  # repos that should get API endpoints
        "stats": {...}
      }
    """
    repos = []

    if username:
        repos.extend(crawl_user_repos(username, limit=limit, gh_token=gh_token))

    if search_query:
        repos.extend(crawl_github(search_query, limit=limit, gh_token=gh_token))

    if not repos and not username and not search_query:
        # Default: crawl user's own repos
        repos.extend(crawl_user_repos("overandor", limit=100, gh_token=gh_token))

    # Deduplicate by full_name
    seen = set()
    unique_repos = []
    for r in repos:
        if r.full_name not in seen:
            seen.add(r.full_name)
            unique_repos.append(r)
    repos = unique_repos

    # Find combinations
    combinations = find_combinations(repos, top_n=top_combinations)

    # Rank repos for serving (repos without APIs that should get endpoints)
    serving_candidates = sorted(repos, key=score_repo_for_serving, reverse=True)
    serving_candidates = [r for r in serving_candidates if not r.has_api][:20]

    stats = {
        "total_repos_discovered": len(repos),
        "commercial_license": len([r for r in repos if r.license in COMMERCIAL_LICENSES]),
        "no_api": len([r for r in repos if not r.has_api]),
        "high_combinability": len([r for r in repos if r.combinability_score > 0.5]),
        "high_novelty": len([r for r in repos if r.novelty_potential > 0.5]),
        "combinations_found": len(combinations),
        "serving_candidates": len(serving_candidates),
        "avg_novelty": sum(c.novelty_score for c in combinations) / max(1, len(combinations)),
    }

    return {
        "repos": [r.to_dict() for r in repos],
        "combinations": [c.to_dict() for c in combinations],
        "serving_candidates": [r.to_dict() for r in serving_candidates],
        "stats": stats,
    }
