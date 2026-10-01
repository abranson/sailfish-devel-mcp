"""Small lexical check for branch-local Sailfish translation comments."""
import re


TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_$][\w$]*|[^\s]')


def ternary_translation_findings(source: str) -> list[dict[str, object]]:
    # Strings and comments are indivisible, so punctuation inside them cannot
    # start a conditional. Delimiter depth keeps nested conditionals separate.
    tokens = [(m.group(), m.start()) for m in TOKEN.finditer(source)
              if not m.group().startswith(("//", "/*"))]
    depths = []
    depth = 0
    pending = []
    pairs = []
    for index, (token, _) in enumerate(tokens):
        if token in ("}", ")", "]"):
            depth -= 1
        depths.append(depth)
        if token == "?" and not (index + 1 < len(tokens) and tokens[index + 1][0] in (".", "?")):
            pending.append((index, depth))
        elif token == ":" and pending and pending[-1][1] == depth:
            question, _ = pending.pop()
            pairs.append((question, index, depth))
        if token in ("{", "(", "["):
            depth += 1
    findings = {}
    for question, colon, depth in pairs:
        end = colon + 1
        while end < len(tokens):
            token, position = tokens[end]
            if depths[end] < depth or (depths[end] == depth and token in (";", ",", "}", ":")):
                break
            # A following QML binding starts a new expression even without ';'.
            if (end > colon + 1 and depths[end] == depth and end + 1 < len(tokens)
                    and tokens[end + 1][0] == ":" and "\n" in source[tokens[end - 1][1]:position]):
                break
            end += 1
        for index in range(question + 1, end):
            token, position = tokens[index]
            if token != "qsTrId" or index + 1 >= len(tokens) or tokens[index + 1][0] != "(":
                continue
            line = source.count("\n", 0, position) + 1
            preceding = source[:position].splitlines()
            # Only contiguous comment lines immediately above this call count.
            if preceding and not preceding[-1].lstrip().startswith("//"):
                preceding.pop()
            comments = []
            for previous in reversed(preceding):
                stripped = previous.strip()
                if not stripped.startswith("//"):
                    break
                comments.append(stripped)
            if not (any(c.startswith("//%") for c in comments)
                    and any(c.startswith("//:") for c in comments)):
                findings[position] = {"line": line, "text": source.splitlines()[line - 1].strip(),
                                      "message": "ternary qsTrId branch needs its own //: and //% comments"}
    return list(findings.values())
