package analyzer

type ctxState int

const (
	ctxNormal ctxState = iota
	ctxLineComment
	ctxBlockComment
	ctxString
	ctxHTMLComment
)

func isInStringOrComment(content string, pos int) bool {
	if pos < 0 || pos >= len(content) {
		return false
	}
	state := ctxNormal
	var delim byte
	for i := 0; i < pos; i++ {
		switch state {
		case ctxNormal:
			switch {
			case content[i] == '/' && i+1 < len(content) && content[i+1] == '/':
				state = ctxLineComment
				i++
			case content[i] == '/' && i+1 < len(content) && content[i+1] == '*':
				state = ctxBlockComment
				i++
			case content[i] == '<' && i+3 < len(content) && content[i:i+4] == "<!--":
				state = ctxHTMLComment
				i += 3
			case content[i] == '"' || content[i] == '\'' || content[i] == '`':
				if i == 0 || content[i-1] != '\\' {
					state = ctxString
					delim = content[i]
				}
			}
		case ctxLineComment:
			if content[i] == '\n' {
				state = ctxNormal
			}
		case ctxBlockComment:
			if content[i] == '*' && i+1 < len(content) && content[i+1] == '/' {
				state = ctxNormal
				i++
			}
		case ctxString:
			if content[i] == delim && (i == 0 || content[i-1] != '\\') {
				state = ctxNormal
			}
		case ctxHTMLComment:
			if content[i] == '-' && i+2 < len(content) && content[i:i+3] == "-->" {
				state = ctxNormal
				i += 2
			}
		}
	}
	return state != ctxNormal
}

type tokType int

const (
	tokIdent tokType = iota
	tokString
	tokNumber
	tokComment
	tokPunct
)

type token struct {
	typ   tokType
	value string
	pos   int
}

func tokenizeJS(input string) []token {
	var toks []token
	i := 0
	for i < len(input) {
		if input[i] == ' ' || input[i] == '\t' || input[i] == '\n' || input[i] == '\r' {
			i++
			continue
		}
		if input[i] == '/' && i+1 < len(input) {
			if input[i+1] == '/' {
				start := i
				i += 2
				for i < len(input) && input[i] != '\n' {
					i++
				}
				toks = append(toks, token{tokComment, input[start:i], start})
				continue
			}
			if input[i+1] == '*' {
				start := i
				i += 2
				for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
					i++
				}
				if i+1 < len(input) {
					i += 2
				}
				toks = append(toks, token{tokComment, input[start:i], start})
				continue
			}
		}
		if input[i] == '"' || input[i] == '\'' || input[i] == '`' {
			delim := input[i]
			start := i
			i++
			for i < len(input) {
				if input[i] == delim && input[i-1] != '\\' {
					i++
					break
				}
				if input[i] == '\n' && delim != '`' {
					break
				}
				i++
			}
			toks = append(toks, token{tokString, input[start:i], start})
			continue
		}
		if isIdentStart(input[i]) {
			start := i
			i++
			for i < len(input) && isIdentPart(input[i]) {
				i++
			}
			toks = append(toks, token{tokIdent, input[start:i], start})
			continue
		}
		if input[i] >= '0' && input[i] <= '9' {
			start := i
			i++
			for i < len(input) && (input[i] >= '0' && input[i] <= '9' || input[i] == '.') {
				i++
			}
			toks = append(toks, token{tokNumber, input[start:i], start})
			continue
		}
		toks = append(toks, token{tokPunct, string(input[i]), i})
		i++
	}
	return toks
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// extractVarBeforeSource scans backwards from sourcePos to find the variable
// name assigned from the source value. Uses token-level analysis.
func extractVarBeforeSource(content string, sourcePos int) string {
	toks := tokenizeJS(content)
	if len(toks) == 0 {
		return ""
	}

	srcIdx := -1
	for j, t := range toks {
		if t.pos >= sourcePos && t.pos < sourcePos+5 {
			srcIdx = j
			break
		}
	}
	if srcIdx <= 0 {
		return ""
	}

	eqIdx := -1
	for j := srcIdx - 1; j >= 0; j-- {
		if toks[j].typ == tokComment {
			continue
		}
		if toks[j].value == "=" {
			eqIdx = j
			break
		}
		if toks[j].typ == tokPunct && toks[j].value != "=" {
			break
		}
	}
	if eqIdx < 0 {
		return ""
	}

	for j := eqIdx - 1; j >= 0; j-- {
		if toks[j].typ == tokComment {
			continue
		}
		if toks[j].typ == tokIdent {
			return toks[j].value
		}
		break
	}
	return ""
}
