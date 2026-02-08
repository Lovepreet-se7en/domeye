# DOMEye

DOMEye is a powerful CLI tool for analyzing web pages for DOM-based vulnerabilities including XSS, CSP violations, and dangerous DOM manipulations.

## Features

- **XSS Detection**: Identifies DOM-based XSS patterns and dangerous sinks
- **CSP Analysis**: Validates Content Security Policy headers and checks for unsafe directives
- **DOM Manipulation**: Detects dangerous DOM operations and event handlers
- **Concurrent Scanning**: Scan multiple URLs simultaneously for faster analysis
- **Multiple Output Formats**: Results in JSON, text, or HTML formats
- **Configurable Checks**: Select specific vulnerability types to scan for

## Installation

### From Source

```bash
git clone https://github.com/Lovepreet-se7en/domeye.git
cd DOMEye
go build -o domeye
```

### Using Go Install

```bash
go install github.com/Lovepreet-se7en/domeye@latest
```

## Usage

### Basic Scan

```bash
domeye scan https://example.com
```

### Scan Multiple URLs

```bash
domeye scan https://example.com https://test.com
```

### Scan from File

```bash
domeye scan --file urls.txt
```

### Specify Output Format

```bash
domeye scan --output json https://example.com
domeye scan --output html https://example.com
```

### Select Specific Checks

```bash
domeye scan --xss --csp https://example.com
domeye scan --dom https://example.com
```

### Concurrent Scanning

```bash
domeye scan --concurrency 10 --file urls.txt
```

### Verbose Mode

```bash
domeye scan --verbose https://example.com
```

## Building

```bash
make build
```

## Testing

```bash
make test
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License - See [LICENSE](LICENSE) for details.
