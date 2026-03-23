/**
 * Gumroad Proxy API
 * Endpoints:
 *   GET  /                  - Service info
 *   GET  /health            - Health check
 *   POST /gumroad/token     - Exchange email+password for Gumroad access token
 *   POST /gumroad/product   - Create a product (requires access_token)
 *   POST /gumroad/upload    - Upload product file (requires access_token + product_id)
 *   GET  /gumroad/products  - List products (requires access_token)
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" },
  });
}

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS });
  }

  // ── / ──
  if (path === "/" || path === "") {
    return json({
      service: "Gumroad Proxy",
      version: "1.0.0",
      endpoints: {
        "POST /gumroad/token": "Get access token via email+password",
        "GET  /gumroad/products": "List products (Bearer token)",
        "POST /gumroad/product": "Create product (Bearer token)",
        "POST /gumroad/upload": "Upload product file (Bearer token)",
      },
    });
  }

  // ── /health ──
  if (path === "/health") {
    return json({ status: "ok", ts: new Date().toISOString() });
  }

  // ── POST /gumroad/token ──
  // Body: { email, password }
  if (path === "/gumroad/token" && req.method === "POST") {
    try {
      const body = await req.json();
      const { email, password } = body;
      if (!email || !password) {
        return json({ error: "email and password required" }, 400);
      }

      // Step 1: GET login page to grab authenticity_token
      const loginPageRes = await fetch("https://app.gumroad.com/login", {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });
      const loginHtml = await loginPageRes.text();
      const cookies = loginPageRes.headers.get("set-cookie") || "";

      // Extract authenticity_token
      const tokenMatch = loginHtml.match(
        /name="authenticity_token"[^>]*value="([^"]+)"/
      );
      const authenticityToken = tokenMatch ? tokenMatch[1] : "";

      if (!authenticityToken) {
        return json({
          error: "Could not extract authenticity_token from login page",
          hint: "Gumroad may have changed their login form",
        }, 500);
      }

      // Step 2: POST login
      const formData = new URLSearchParams({
        authenticity_token: authenticityToken,
        email,
        password,
        next: "",
      });

      const loginRes = await fetch("https://app.gumroad.com/login", {
        method: "POST",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: cookies.split(",").map((c) => c.split(";")[0]).join("; "),
          Referer: "https://app.gumroad.com/login",
        },
        body: formData.toString(),
        redirect: "manual",
      });

      const responseCookies = loginRes.headers.get("set-cookie") || "";
      const location = loginRes.headers.get("location") || "";

      if (loginRes.status === 302 && location.includes("gumroad.com")) {
        // Login succeeded, now get the API access token
        // Navigate to settings to find/generate token
        const allCookies = [
          ...cookies.split(",").map((c) => c.split(";")[0]),
          ...responseCookies.split(",").map((c) => c.split(";")[0]),
        ].join("; ");

        return json({
          success: true,
          message: "Login successful",
          redirect: location,
          cookies: allCookies,
          note: "Use cookies to access Gumroad API settings page and generate access_token",
        });
      } else {
        return json({
          error: "Login failed",
          status: loginRes.status,
          location,
        }, 401);
      }
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── GET /gumroad/products ──
  if (path === "/gumroad/products" && req.method === "GET") {
    const token = url.searchParams.get("access_token") ||
      (req.headers.get("Authorization") || "").replace("Bearer ", "");
    if (!token) return json({ error: "access_token required" }, 401);

    const res = await fetch(
      `https://api.gumroad.com/v2/products?access_token=${token}`
    );
    const data = await res.json();
    return json(data, res.status);
  }

  // ── POST /gumroad/product ──
  // Body: { access_token, name, description, price (cents), url (custom) }
  if (path === "/gumroad/product" && req.method === "POST") {
    try {
      const body = await req.json();
      const { access_token, name, description, price = 0, customUrl } = body;
      if (!access_token || !name) {
        return json({ error: "access_token and name required" }, 400);
      }

      const params = new URLSearchParams({
        access_token,
        name,
        description: description || "",
        price: String(price),
      });
      if (customUrl) params.set("custom_permalink", customUrl);

      const res = await fetch("https://api.gumroad.com/v2/products", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
      });
      const data = await res.json();
      return json(data, res.status);
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /gumroad/upload ──
  // Multipart: access_token (field), product_id (field), file (file field)
  if (path === "/gumroad/upload" && req.method === "POST") {
    try {
      const formData = await req.formData();
      const accessToken = formData.get("access_token") as string;
      const productId = formData.get("product_id") as string;
      const file = formData.get("file") as File;

      if (!accessToken || !productId || !file) {
        return json(
          { error: "access_token, product_id, and file are required" },
          400
        );
      }

      // Upload file to Gumroad product
      const uploadForm = new FormData();
      uploadForm.append("access_token", accessToken);
      uploadForm.append("file", file, file.name);

      const res = await fetch(
        `https://api.gumroad.com/v2/products/${productId}/product_files`,
        {
          method: "POST",
          body: uploadForm,
        }
      );
      const data = await res.json();
      return json(data, res.status);
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /gumroad/publish ──
  // Body: { access_token, product_id }
  if (path === "/gumroad/publish" && req.method === "POST") {
    try {
      const body = await req.json();
      const { access_token, product_id } = body;
      if (!access_token || !product_id) {
        return json({ error: "access_token and product_id required" }, 400);
      }

      const params = new URLSearchParams({ access_token, published: "true" });
      const res = await fetch(
        `https://api.gumroad.com/v2/products/${product_id}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: params.toString(),
        }
      );
      const data = await res.json();
      return json(data, res.status);
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  return json({ error: "Not found", path }, 404);
}

console.log("Gumroad Proxy v1.0 starting...");
Deno.serve(handler);
