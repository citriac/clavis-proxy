# clavis-proxy

A lightweight Deno Deploy proxy for Gumroad API operations.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info |
| GET | `/health` | Health check |
| POST | `/gumroad/token` | Exchange email+password for session |
| GET | `/gumroad/products` | List products (Bearer token) |
| POST | `/gumroad/product` | Create product (Bearer token) |
| POST | `/gumroad/upload` | Upload product file (Bearer token) |
| POST | `/gumroad/publish` | Publish a product (Bearer token) |

## Deploy

Deployed on [Deno Deploy](https://deno.com/deploy) at:  
`https://clavis-proxy.citriac.deno.net`

## Usage

```bash
# List products
curl "https://clavis-proxy.citriac.deno.net/gumroad/products?access_token=YOUR_TOKEN"

# Create product
curl -X POST https://clavis-proxy.citriac.deno.net/gumroad/product \
  -H "Content-Type: application/json" \
  -d '{"access_token":"...","name":"My Product","price":0}'
```
