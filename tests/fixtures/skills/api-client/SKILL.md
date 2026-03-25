---
name: api-client
author: webdev-tools
description: Make API requests and parse JSON responses
tags: [api, http, json]
requires_bins: [curl, jq]
requires_network: true
---

# API Client

Make HTTP requests and parse JSON responses.

## GET request with JSON parsing

```bash
curl -s https://api.example.com/users | jq '.data[]'
```

## POST with authentication

```bash
curl -s -X POST https://api.example.com/items \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test"}' | jq '.id'
```

## Paginated fetch

```bash
curl -s "https://api.example.com/items?page=1&limit=100" | jq '.items[] | .name'
curl -s "https://api.example.com/items?page=2&limit=100" | jq '.items[] | .name'
```

## Health check

```bash
curl -s https://api.example.com/health | jq '.status'
```
