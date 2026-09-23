# Crossing Thresholds Issue Tracker — standalone version

A self-contained tech issue tracker with its own email/password accounts and its own
database file. No claude.ai account or service is used anywhere in this version.

- Tech staff report issues by school.
- One tech director (enforced automatically — promoting someone new to director
  quietly moves the previous director back to tech staff) triages everything,
  can ask for more information, or escalate to the board.
- Board members take escalated issues and resolve them.
- An admin account creates every other account and manages the school list.

## Requirements

- Node.js 18 or newer.

## Running it locally

```bash
npm install
npm start
```

Then open http://localhost:3000. The first time it's opened, it will ask you to
create the admin account — that's the only account created this way. Every other
account (director, board members, staff) is created by the admin from the
**People and schools** tab, using a temporary password you share with them directly
(there is no automatic email — this app doesn't send email at all).

## Deploying it somewhere real

This is a plain Node.js/Express app, so it runs on almost any host that runs
Node: Render, Railway, Fly.io, a VPS, or a school's own server. In broad strokes:

1. Push this folder to a git repository (or upload it directly if the host allows that).
2. Set the start command to `npm start` (or `node server.js`).
3. Set two environment variables on the host:
   - `SESSION_SECRET` — any long random string you generate once and keep. Without
     this, a random one is used and everyone is signed out whenever the server restarts.
   - `COOKIE_SECURE=true` — once your site is served over HTTPS (which every one of
     the hosts above provides automatically). Leave this unset for local testing over
     plain http://localhost.
4. Deploy. Open the site's URL and go through the same first-run setup as above.

## Where the data lives

Everything (accounts, schools, issues) is stored in a single file at
`data/db.json`, created automatically the first time the server runs. Back this
file up periodically — there is no separate database server to manage, but
there's also no automatic backup. If your host wipes its filesystem between
deploys (some free tiers do), attach a persistent disk/volume and point
`data/db.json` at it, or swap in a real database later.

## Security notes

- Passwords are hashed with bcrypt before being stored — the plain password is
  never saved anywhere.
- Sessions are a signed cookie, not stored server-side; they simply expire after 7 days.
- There's no email-based password reset. If someone forgets their password, the
  admin resets it for them from **People and schools**.
- This is sized for an internal district tool, not a public-facing service —
  put it behind your school network or a login-only URL, and keep `SESSION_SECRET`
  private.
"# CT-Issue-T" 
