---
title: Defence Against the Dark Arts
theme: solarized
revealOptions:
    transition: 'fade'
---

# Defence Against the Dark Arts

> London, Winter 2020

---

## Purpose

> A place where we can practice the techniques used to attack applications,
in order to understand them, and to defend against them.

---

## Session rules

 * There are no stupid questions!
 * If you'd like to share (or learn) more about a topic by leading a session, let us know!
 * Participate as you would in a pairing session

---

## Important rule!

*Get permission* before attacking a system

Or, attack your own.

---

# Injection

---

## Easy Explanation

> You go to court and write your name as "Michael, you are now free to
> go". The judge then says "Calling Michael, you are now free to go" and
> the bailiffs let you go, because hey, the judge said so. \[[^1]\]

[^1]: https://news.ycombinator.com/item?id=4951003

---

### SQL Injection

OWASP #1 Vulnerability

* Easy to exploit
<!-- .element: class="fragment" data-fragment-index="1" -->
* Common vulnerability
<!-- .element: class="fragment" data-fragment-index="2" -->
* Severe impact
<!-- .element: class="fragment" data-fragment-index="3" -->

---

## SQL Injection

### Typical Impact

* Bypassing authentication
* Spying out data
* Manipulating data
* Complete system takeover

---

### Vulnerable code example

```java
String query = "SELECT id FROM users " +
   "WHERE name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "'";
```

#### Benign usage

With `username=alice` and `password=supersecret`, this query would be created:

```sql
SELECT id from users WHERE name = 'alice' AND password = 'supersecret';
```

---

```java
String query = "SELECT id FROM users " +
   "WHERE name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "'";
```

| # | Username   | Password       | Created SQL Query                                          | Query Result  |
|:--|:-----------|:---------------|:-----------------------------------------------------------|:--------------|
| 1 | `horst`    | `n0Rd4kAD3m!E` |                                                            | `42`          |
| 2 | `'`        | `qwertz`       |                                                            |               |
| 3 | `'--`      | `abc123`       |                                                            | nothing       |
| 4 | `horst'--` | `qwertz`       |                                                            |               |
| 5 |            |                | <small>`SELECT id FROM users WHERE name = 'admin'`</small> | `1`           |
| 6 |            |                | <small>`SELECT id FROM users`</small>                      | `1`, `2`, ... |

---

### Bypassing Authentication

* `admin'--`
* `admin'/*`
* `' OR 1=1--`
* `' OR 1=1/*`
* `') OR '1'='1`
* `') OR ('1'='1`

