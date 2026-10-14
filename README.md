# My Spends: setup guide

A private expense tracker that installs on your Android phone like an app (a PWA).
No server, no database to run. Data lives **encrypted** in a **private GitHub repo**.

## How it fits together

| Piece | Where | Visibility |
|---|---|---|
| App files (this folder) | GitHub repo `money-tracker` + GitHub Pages | Public shell, contains no data and no token |
| Your expenses | GitHub repo `money-data` | **Private**, and every file is AES-256 encrypted with your PIN |
| Token + cache | Your phone only | Encrypted with your PIN |

## Step 1: Create the two repos

1. On GitHub, create **`money-data`**, set it to **Private**, tick "Add a README". Leave it otherwise empty.
2. Create **`money-tracker`**, set it to **Public** (free GitHub Pages needs a public repo; the app contains nothing secret).

## Step 2: Upload the app

1. Open `money-tracker` repo, **Add file, Upload files**.
2. Unzip this package and drag in everything: `index.html`, `style.css`, `app.js`, `sw.js`, `manifest.webmanifest`, and the `icons` folder (keep the folder).
3. Commit to `main`.
4. **Settings, Pages**, Source: *Deploy from a branch*, Branch: `main`, folder `/ (root)`, Save.
5. After about a minute your app is at `https://<your-username>.github.io/money-tracker/`.

## Step 3: Create the access token

1. GitHub, profile picture, **Settings, Developer settings, Personal access tokens, Fine-grained tokens, Generate new token**.
2. Resource owner: you. **Repository access: Only select repositories, choose `money-data`** (only that one).
3. Permissions, **Repository permissions: Contents = Read and write**. (Metadata read-only is added automatically.)
4. Pick an expiry you're comfortable with. When it expires: Settings in the app, **Update GitHub token**.
5. Generate and copy the token (starts with `github_pat_`).

## Step 4: Install on your phone

1. Open the Pages URL in **Chrome on Android**.
2. First-run screen: enter `your-username/money-data`, paste the token, choose a PIN.
3. Chrome menu (three dots), **Install app** / **Add to Home screen**.

From then on, open it from the home-screen icon. Add expenses with the **+** button.

## Using it

- **+** : amount, area, purpose, date/time (defaults to now), paid via (UPI/Cash/Card/Other).
- **Home** : month total, daily average, budget bar, spending by area, daily chart, recent items.
- **History** : search, filter by area, tap any row to edit or delete, "All months" toggle.
- **Settings** : monthly budget, add/remove areas, sync now, CSV export, lock, update token.
- Works offline: entries save on the phone and sync when you're back online (status shown top right).
- Auto-locks after 1 minute in the background.

## Security notes (read these)

- **PIN strength matters.** Your data is encrypted with a key derived from the PIN (PBKDF2, 600,000 rounds). If someone ever got your encrypted repo files, a short numeric PIN could be brute-forced offline. Use **8+ digits**, or a passphrase (tap "Use letters instead of digits" on the lock screen).
- **Forgot the PIN = data is unrecoverable.** Export a CSV from Settings now and then.
- The app refuses to set up against a public repo.
- The token is stored only on your phone, encrypted with your PIN. Don't paste it anywhere else.
- Keep your phone's own screen lock on. An unlocked phone with the app open is the real remaining risk.
- Item amounts, areas, notes and times are all inside the encrypted files. GitHub can see only file names (the month, like `2026-10.enc`) and commit times.

## Second device or new phone

Open the same URL, enter the same repo, token (create a new one if needed) and the **same PIN**. The app detects the existing data and verifies the PIN against it.

## Updating the app later

Replace the files in the `money-tracker` repo. The app updates itself: **open it twice** to see the new version (the first open loads the new files in the background). If you change files, bump `V` in `sw.js` (e.g. `spends-v2`).
