# xssrecon 🕵️‍♂️

`xssrecon` is a powerful tool for detecting Cross-Site Scripting (XSS) vulnerabilities. It automatically scans for both normal (server-side) and DOM-based (client-side) reflections, analyzing how user input is handled and checking for special characters that could be used in XSS attacks.

## 🚀 Installation

To install `xssrecon`, you need to have Go installed on your system. You can install `xssrecon` with the following command:

```bash
go install -v github.com/bytes-Knight/xssrecon@latest
```

## 💡 Usage

You can use `xssrecon` by providing a list of URLs through standard input. The tool will then process each URL and provide a detailed analysis of potential XSS vulnerabilities.

### Example

```bash
cat urls.txt | xssrecon
```

Where `urls.txt` contains a list of URLs to be tested, such as:

```
http://example.com/search?query=test
http://example.com/user/{payload}
```

## ⚙️ Command-Line Flags

`xssrecon` supports the following command-line flags:

| Flag              | Description                                                              | Default                                                                       |
|-------------------|--------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `-H`, `--user-agent`  | Custom User-Agent header for HTTP requests.                              | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36` |
| `-t`, `--timeout`       | Timeout for HTTP requests in seconds.                                    | `15`                                                                          |
| `-s`, `--skipspecialchar` | Only check for the presence of the test string in the response.          | `false`                                                                       |
| `--no-color`      | Do not use colored output.                                               | `false`                                                                       |
| `--silent`        | Suppress the banner and other non-essential output.                     | `false`                                                                       |
| `--version`       | Print the version of the tool and exit.                                  | `false`                                                                       |
| `--verbose`       | Enable verbose output for debugging purposes.                            | `false`                                                                       |
| `--json`          | Output results in JSON format.                                           | `false`                                                                       |

## 🤝 Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or create a pull request.

## 📄 License

This project is licensed under the MIT License.
