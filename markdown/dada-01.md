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

## Plan

A series of sessions focusing on aspects of security:

 * Web Applications
 * Cryptography?
 * Linux security?
 * PAS???
 * ...

If you have something interesting to share let us know!

---

## Important rule!

*Get permission* before attacking a system

Or, attack your own.

---

## Web Application Hacking #101

---

## OWASP Top 10

1.  Injection
2.  Broken Authentication
3.  Sensitive Data Exposure
4.  XML External Entities
5.  Broken Access Control
6.  Security Misconfiguration
7.  Cross-Site-Scripting (XSS)
8.  Insecure Deserialization
9.  Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

---

### OWASP Juice Shop

Example app exhibiting the 10 top OWASP vulnerabilities
and more

---

For a realistic feel, install on Heroku:

* Create a free account https://signup.heroku.com
* Login https://id.heroku.com/login
* Click the 'one click deploy' button on [here](https://github.com/bkimminich/juice-shop#deploy-on-heroku-free-0month-dyno)
* Install takes 5-10 minutes

Alternatively, checkout https://github.com/bkimminich/juice-shop and `npm install` etc.

---

## Hacking Rules

 * Do not look at the source code on GitHub
 * Do not look at GitHub issues, PRs etc.
 * Do not cheat (with online tutorials or walkthroughs) before trying

---

## Exercise

Explore the Juice Bar, e.g.

* Browse products
* Register an account
* Buy some products
* Checkout
* Leave a review
* View feedback

---

## Interesting Finds?

* Did anything appear strange / broken?
* Did you trigger an hack alerts?
* Did you notice any application errors?
* What stack is the application running on?
* What sort of requests are made to the back end?
* Is all the front-end using the single page app model?

---

## Challenge

> Find a page keeping track of your hack score!

---

## Exercise

Try some of the level 1 hacks, e.g.

* DOM XSS
* 0-star review
* Retrieve the cat photo

---

## What impact do these problems have?

* DOM XSS
* Client-side only validation
* Broken encoding

---

## Challenge

> Find the admin site

---

## Challenge

> Get past the authorization error!

---

## A solution:

SQL Injection on login page

* Try some SQL special characters
* Look for information in error messages
* Think about how we can extend the query
* How do we exclude the rest of it?

---

## Next time

* XSS In Depth
