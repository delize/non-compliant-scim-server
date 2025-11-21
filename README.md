# Non-Compliant SCIM Server

## What Fresh Hell Is This?

Welcome to the Non-Compliant SCIM Server, a lovingly crafted dumpster fire of a SCIM 2.0 implementation. This server is deliberately broken in very specific ways because, apparently, that's what we need to test real world scenarios that exist in Applications that can't code SCIM properly.

## Why Does This Exist?

In a perfect world, every SCIM server would follow the RFC specifications to the letter. But we don't live in a perfect world. We live in a world where enterprise software vendors ship SCIM implementations that are... creative interpretations of the spec, shall we say.

This server simulates two real-world broken SCIM behaviors that actually exist in production systems:

### 1. The Snowflake Special: "Members? Never heard of them."

**What it does:** Rejects any attempt to add members to groups with a 400 Bad Request.

**Why:** Some systems (looking at you, Snowflake) don't have a way to verify that users exist before adding them to groups. Rather than just, you know, trusting the request and dropping members that don't exist, they reject it entirely. Groups can exist, but they must remain forever empty. Like my soul.

**The behavior:**
- Creating a group with members? 400 error.
- PATCH to add members? 400 error.
- Trying to populate groups? Absolutely not. 400 error.

### 2. The Microsoft Move: "Group renames are for quitters."

**What it does:** Returns a 409 Conflict when you try to rename a group.

**Why:** Microsoft's SCIM implementation has decided that group renames are just too complicated. Once you name a group, that name is carved in stone. Forever. Like a terrible tattoo you got in college. Then Okta goes and deactivates the push group silently. We can't mimic Okta's behavior for the app exactly, but we can respond with an error.

**The behavior:**
- Try to change displayName? 409 Conflict.
- PATCH with a new displayName? 409 Conflict.
- Desperately want to fix that typo? 409 Conflict.

## Technical Details (For Those Who Care)

This server is otherwise RFC-compliant (RFCs 7642, 7643, 7644). It properly implements:

- **Dynamic User Provisioning:** Accepts any users Okta pushes via POST /Users or PUT /Users/{id}
- **User Discovery:** GET /Users with filtering support
- **Group Management:** Create, read, update, delete groups (except for the deliberately broken parts)
- **SCIM Schemas:** Proper User and Group schemas
- **Resource Types:** Full discovery support
- **PATCH Operations:** Handles both path-based and path-less formats (the broken ones just error out)

The user store starts empty and accepts any email/username Okta wants to provision. This way you can test with real users instead of hardcoded test accounts.

## Running This Monstrosity

### Prerequisites

- Docker (because who wants to deal with Python environments)
- An Okta trial account (for testing)
- A sense of humor about enterprise software

### Option 1: Use the Pre-Built Image (Recommended)

Why waste time building when it's already available?

```bash
# Pull the latest image from GitHub Container Registry
docker pull ghcr.io/delize/non-compliant-scim-server:latest

# Run the container
docker run -d -p 50001:5000 --name scim-test ghcr.io/delize/non-compliant-scim-server:latest

# Watch the chaos unfold
docker logs -f scim-test
```

### Option 2: Build It Yourself (For the Control Freaks)

If you don't trust pre-built images or just enjoy waiting for Docker builds:

```bash
# Build the Docker image
docker build -t non-compliant-scim-server .

# Run the container
docker run -d -p 50001:5000 --name scim-test non-compliant-scim-server

# Watch the chaos unfold
docker logs -f scim-test
```

### Exposing Your Local Server to Okta (Because Okta Doesn't Know About Localhost)

Okta needs a public URL to talk to your SCIM server. Unless you're running this on a cloud server (and let's be honest, you're probably testing on your laptop), you'll need to expose your local server to the internet. Enter cloudflared tunnel, Cloudflare's gift to developers who don't want to mess with ngrok subscriptions or port forwarding.

**Install cloudflared:**

Follow the instructions at [https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)

Or if you're on macOS with Homebrew:

```bash
brew install cloudflared
```

**Create a tunnel to your local server:**

```bash
# If you mapped it to a different port (e.g., 50001:5000)
cloudflared tunnel --url http://localhost:50001
```

Cloudflare will give you a public URL that looks like `https://randomly-generated-words.trycloudflare.com`. This URL is temporary and changes every time you restart the tunnel, which is perfect for testing and terrible for anything else.

Use this URL as your SCIM Base URL in Okta:
```
https://randomly-generated-words.trycloudflare.com/scim/v2
```

**Pro tip:** Keep the cloudflared terminal window open so you can see the tunnel is active. When you're done testing, just Ctrl+C to kill it. The internet is dangerous enough without leaving random tunnels open.

### Configuration

The server uses:
- **Port:** 5000 inside the container (map to whatever you want outside)
- **Auth Token:** `SCIM_TOKEN` (hardcoded because this is a test server, not Fort Knox)
- **Base URL:** `/scim/v2`

Configure Okta to use:
- **SCIM Base URL:** `https://randomly-generated-words.trycloudflare.com/scim/v2`
- **Auth:** Bearer token `SCIM_TOKEN`

## What You'll See

When Okta tries to provision users and groups, you'll see detailed debug logs showing:

1. User provisioning (SUCCESS) - Because we're not monsters
2. Group creation (SUCCESS) - Empty groups are fine
3. Member addition attempts (FAILURE) - Here's where the fun begins
4. Group rename attempts (FAILURE) - If you're testing that scenario

The server logs every HTTP request with full headers and body content, so you can see exactly what Okta is sending and why it's failing.

## Expected Okta Workflow

* **Step 1:** Okta searches for users (GET /Users) - finds none
*  **Step 2:** Okta provisions users (POST /Users) - SUCCESS
* **Step 3:** Okta creates groups with empty members (POST /Groups) - SUCCESS
* **Step 4:** Okta tries to add members to groups (PATCH /Groups/{id}) - FAILURE (400)
* **Step 5:** Okta cries a little inside

If you test group renames:
* **Step 6:** Okta tries to rename a group (PATCH /Groups/{id}) - FAILURE (409)
* **Step 7:** Okta questions its life choices

## Is This Production Ready?

Absolutely not. This is a test server designed to fail in specific ways. If you're looking for a real SCIM server implementation, this is not it. This is the "what not to do" example.

## Contributing

If you find other creative ways that production SCIM servers are broken and want to add them, pull requests are welcome. Misery loves company.

## License

Do whatever you want with this. If you're using it in production, please seek professional help.

## Final Thoughts

The fact that this server needs to exist says more about the state of enterprise software than any documentation ever could. May your SCIM implementations be less broken than the ones we're simulating here.

Happy testing, and remember: it's not a bug, it's a feature simulation.
