"""Editable signature tables. Heuristic: extend as new agents appear."""

# (UA token, vendor, product, role)
AI_CRAWLERS = [
    ("GPTBot", "OpenAI", "GPTBot", "training crawler"),
    ("OAI-SearchBot", "OpenAI", "OAI-SearchBot", "search crawler"),
    ("ChatGPT-User", "OpenAI", "ChatGPT-User", "on-demand agent fetch"),
    ("ClaudeBot", "Anthropic", "ClaudeBot", "training crawler"),
    ("Claude-User", "Anthropic", "Claude-User", "on-demand agent fetch"),
    ("Claude-SearchBot", "Anthropic", "Claude-SearchBot", "search crawler"),
    ("anthropic-ai", "Anthropic", "anthropic-ai", "legacy crawler"),
    ("PerplexityBot", "Perplexity", "PerplexityBot", "search crawler"),
    ("Perplexity-User", "Perplexity", "Perplexity-User", "on-demand agent fetch"),
    ("GoogleOther", "Google", "GoogleOther", "research crawler"),
    ("Google-CloudVertexBot", "Google", "Vertex AI crawler", "agent crawler"),
    ("Bytespider", "ByteDance", "Bytespider", "training crawler"),
    ("Amazonbot", "Amazon", "Amazonbot", "crawler"),
    ("Applebot", "Apple", "Applebot", "crawler"),
    ("meta-externalagent", "Meta", "meta-externalagent", "training crawler"),
    ("meta-externalfetcher", "Meta", "meta-externalfetcher", "on-demand agent fetch"),
    ("FacebookBot", "Meta", "FacebookBot", "crawler"),
    ("CCBot", "Common Crawl", "CCBot", "dataset crawler"),
    ("cohere-ai", "Cohere", "cohere-ai", "crawler"),
    ("MistralAI-User", "Mistral AI", "MistralAI-User", "on-demand agent fetch"),
    ("DuckAssistBot", "DuckDuckGo", "DuckAssistBot", "assistant fetch"),
    ("YouBot", "You.com", "YouBot", "search crawler"),
    ("Diffbot", "Diffbot", "Diffbot", "extraction crawler"),
    ("PetalBot", "Huawei", "PetalBot", "crawler"),
    ("Timpibot", "Timpi", "Timpibot", "crawler"),
    ("ImagesiftBot", "Hive", "ImagesiftBot", "crawler"),
    ("Omgilibot", "Webz.io", "Omgilibot", "crawler"),
]

SCANNERS = ["nuclei", "sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster",
            "dirb", "ffuf", "wfuzz", "feroxbuster", "burpsuite", "zaproxy", "acunetix", "nessus",
            "openvas", "wpscan", "whatweb", "arachni", "skipfish", "projectdiscovery", "censys",
            "shodan", "netsparker"]

SCRIPTED_CLIENTS = ["curl", "wget", "python-requests", "python-httpx", "aiohttp", "python-urllib",
                    "go-http-client", "okhttp", "axios", "node-fetch", "undici", "libwww-perl",
                    "apache-httpclient", "postmanruntime", "httpie", "scrapy", "reqwest", "java/"]

AUTOMATION = ["headlesschrome", "playwright", "puppeteer", "selenium", "phantomjs", "webdriver"]

AGENT_HINTS = ["langchain", "llamaindex", "browser-use", "browseruse", "browserbase", "stagehand",
               "autogpt", "crewai", "openai", "anthropic", "claude", "gemini", "perplexity",
               "agentic", "ai-agent", "aiagent"]

# DOM markers of agent browsers/extensions (client-side, editable). Regex tested on id/class of injected nodes.
AGENT_DOM_REGEX = r"(ai[-_]?agent|agent[-_]?(overlay|bar|panel|cursor|ui)|copilot|genspark|comet|atlas|operator|browser[-_]?use|assistant[-_]?(sidebar|panel))"
AGENT_DOM_SELECTORS = ["#genspark-float-bar"]

HOSTING_HINTS = ["amazon", "aws", "google", "gcp", "azure", "microsoft", "digitalocean", "ovh", "hetzner",
                 "linode", "akamai", "vultr", "oracle", "cloudflare", "contabo", "scaleway", "alibaba",
                 "tencent", "leaseweb", "choopa", "m247", "datacamp"]

def _has(ua_l, toks):
    for t in toks:
        if t in ua_l:
            return t
    return None

def parse_ua(ua: str) -> dict:
    ual = (ua or "").lower()
    out = {"crawler": None, "scanner": None, "client": None, "automation": None, "hint": None, "tool": "unknown"}
    for tok, vendor, product, role in AI_CRAWLERS:
        if tok.lower() in ual:
            out["crawler"] = {"token": tok, "vendor": vendor, "product": product, "role": role}
            break
    out["scanner"] = _has(ual, SCANNERS)
    out["client"] = _has(ual, SCRIPTED_CLIENTS)
    out["automation"] = _has(ual, AUTOMATION)
    out["hint"] = _has(ual, AGENT_HINTS)
    if not ua:
        out["tool"] = "empty-ua"
    elif out["crawler"]:
        out["tool"] = out["crawler"]["product"]
    elif out["scanner"]:
        out["tool"] = out["scanner"]
    elif out["automation"]:
        out["tool"] = out["automation"]
    elif out["client"]:
        out["tool"] = out["client"]
    elif "mozilla/" in ual:
        out["tool"] = "browser"
    return out
