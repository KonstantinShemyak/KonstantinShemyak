---
layout: default
title: Index
---

# All pages:

<ul>
  {% assign this = page.url %}
  {% for page in site.pages %}
    {% if page.title and page.url != this %}
      <li><a href="{{ page.url }}">{{ page.title }}</a></li>
    {% endif %}
  {% endfor %}  <!-- page -->
</ul>

