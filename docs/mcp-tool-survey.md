# I looked at 1,384 tools across 28 MCP servers. Here's what the attack surface actually looks like.

> Quick context if you're new to this: an **MCP server** is a plug-in that gives
> an AI agent a set of **tools** it can call, like "fetch this URL," "run this
> database query," or "send this email." There are hundreds of open-source MCP
> servers now. This writeup measures what those tools actually let an agent do,
> and how often the risky combinations sit side by side.

> Method note. The numbers are a **snapshot taken on 2026-10-20** of 28 popular
> Python MCP servers (plus the reference-servers repo), produced with the
> reproducible harness in [`examples/mcp-survey/`](../examples/mcp-survey).
> Upstream repos change over time, so re-running this later gives somewhat
> different counts. The harness is deterministic for a given set of checkouts,
> and `servers.yaml` lists exactly what was surveyed. Everything below is read
> from **public source code**. No server was connected to or executed. The
> capability labels are rough heuristics (see the caveats), and this writeup
> deliberately does **not** call anything a vulnerability.

I kept running into MCP servers where one tool fetches a web page and another
tool runs a command, both handed to the same agent, with nothing telling the
model which one is dangerous. Instead of guessing how common that is, I decided
to measure it.

So I pulled the tool definitions straight from the source code of the most
popular Python MCP servers on GitHub (AWS Labs, Google Workspace, Atlassian,
Home Assistant, Snowflake, the Neo4j / Redis / Qdrant / Chroma / Milvus database
servers, the Office / Excel document servers, Telegram, and more), and ran
[AgentSploit](https://github.com/agentsploit/agentsploit)'s inventory checks plus
a simple source/sink classifier over them. That comes to **1,384 tools across 28
servers.** The reproducible harness is at the bottom.

## Finding 1: tool descriptions are already full of instructions to the model

A tool's description is just text, and the AI reads it. The "tool poisoning"
attack is built on that fact: if an attacker can slip instructions into a
description, the model may follow them. (Think of it like hiding a note in a
manual that the reader obeys without question.)

What the survey shows is that **normal, legitimate servers already write their
descriptions as direct orders to the model.** These are real examples, and all
of them are completely harmless:

> "Before using this tool, provide a 1-3 sentence explanation…" (AWS Labs)
> "CRITICAL: YOU MUST CALL inspect_doc_structure FIRST…" (Google Workspace)
> "🔴 PREREQUISITE: Before calling this tool, you MUST first call `…`" (AWS Labs)

Those are good-faith usage notes. The problem is that, at the level of plain
text, they look exactly like an injected `IGNORE ALL PREVIOUS INSTRUCTIONS`. A
pattern-based scanner (AgentSploit's included) flags both the same way. I went
through all **9** matches by hand, spread across **4 independent vendors** (AWS,
Google, Home Assistant, arXiv), and every single one was **benign**. That is the
real finding: there's no clean way to tell a harmless instruction-style
description from a malicious one, because the whole ecosystem already uses that
same channel on purpose.

## Finding 2: the risky ingredients sit side by side, everywhere

I sorted every tool into two buckets:

- A **source** is a tool that pulls in outside content you don't control. In the
  data, that means it takes an argument like `url`, `uri`, `path`, or `document`,
  or its name looks like `fetch` / `read` / `search` / `crawl`.
- A **sink** is a tool that does something with real impact. That means a name
  like `exec` / `run` / `query` / `write` / `send` / `delete`, or an argument
  like `command`, `query`, or `code`.

The danger isn't either bucket on its own. It's having both in front of the same
agent, so that something the agent *read* can flow into something the agent
*does*.

Across 1,384 tools:

| | count |
|---|---|
| untrusted-content **sources** | 239 |
| high-impact **sinks** | 384 |
| tools that are **both** (they ingest *and* act) | **59** |
| servers that expose at least one source **and** one sink in the same context | **14 / 28** |

The 59 "both" tools are the sharpest edge. A single tool that pulls in a URL or a
file and also runs a query or a command is a one-call bridge from untrusted input
straight to a real action, if the content it pulls is attacker-controlled. For
example `search_table(url)` that also takes a `query`, or `run_query(db_endpoint,
sql)`, or the Google Workspace and Office document tools that read a document and
write it back. And 14 of the 28 servers put sources and sinks in the same agent
context with nothing marking one as untrusted or the other as dangerous. (The
harness prints the full list so you can check it yourself. A few are weak
matches. For instance AWS IAM's `create_user` trips the filter on an IAM `path`
argument, which isn't really outside content.)

## Finding 3: the sinks are wide open

Plenty of the sink tools take a raw string with **no `enum`, `pattern`, or
`format` constraint** on it, like `executeQuery(query)`,
`run_opencypher_query(query)`, or `read_documentation(url)`. (Those constraints
are the schema's way of saying "only these specific values are allowed." Without
them, the field accepts anything.) That's by design for a query tool. It's also
exactly the kind of wide-open sink that turns "the agent read a poisoned page"
into "the agent ran the attacker's SQL."

## This is not a list of vulnerabilities

To be clear: none of the above is a bug in these servers. A source-to-sink chain
only becomes a real exploit when two things both happen: untrusted input actually
reaches a source, and the agent actually carries it over to a sink. Both of those
depend on how the server gets deployed and wired together, not on the code
itself. Proving a real chain needs a live agent, which is what AgentSploit's
permission-graph mapper and canary runner are for. That's out of scope for a
static survey like this one.

## What actually helps

- Treat third-party tool descriptions as untrusted input to your own system
  prompt, and keep them in an isolated context instead of pasting them in raw.
- Constrain what sink arguments accept (`enum` / `pattern` / `format`) rather
  than taking any raw string.
- Don't put untrusted-content sources and high-impact sinks in the same agent's
  tool set without an isolation or confirmation step in between.

## Reproduce it

```bash
git clone https://github.com/agentsploit/agentsploit && cd agentsploit
pip install -e .
cd examples/mcp-survey            # edit servers.yaml to pick targets
python survey.py collect          # read tool definitions from public source
python survey.py scan             # run agentsploit's inventory checks
python survey.py aggregate        # print the findings table
python survey.py surface          # run the source/sink classification
```

## Caveats

- The labels are heuristic. Sources are limited to outside-content signals
  (`url` / `uri` / `path` / `document` arguments, `fetch` / `crawl` / `scrape`
  names), and the matching is token-based. It's still a guess at what a tool can
  do, not a traced data-flow. So read the counts as "could plausibly be," and
  trust the overall shape more than any single number. The shape is the sturdy
  part: most servers mix ingestion and action, and 59 tools do both in one call.
- Static reading misses some tools. It can't resolve Pydantic-schema arguments or
  cross-file enums, and it skips custom tool frameworks (serena, mcp-obsidian,
  and excel-mcp-server each extracted 0, because they register tools through
  their own bespoke class instead of the standard SDK). It also skips every
  non-Python server. So every tool count here is a floor, not a ceiling.
- Pattern-based checks flag harmless text too. I reviewed the matches by hand, so
  this writeup reports the reviewed conclusion, not the raw machine count.

The tool is Apache-2.0: https://github.com/agentsploit/agentsploit. Ideas and
pull requests welcome.
