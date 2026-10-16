# xss <script>alert('heading-injection')</script> fixture

<script>alert('body-injection')</script>

```sh
echo <img src=x onerror=alert(1)> done
```

This README is hostile markup for HTML-escaping tests. Extracted
commands and headings must render as inert text in reports, never as
executable HTML/JS.
