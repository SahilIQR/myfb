# MYFB Account Portal

This application provides account registration, username/password sign-in, user profiles, and private customer-to-administrator chat rooms. It does not accept deposits, process withdrawals, or provide investment transactions.

## Run locally

1. Install Node.js 22 or newer.
2. Install dependencies with `npm install`.
3. Configure an administrator account in the environment:

   ```powershell
   $env:ADMIN_USERNAME = "myfbadmin"
   $env:ADMIN_PASSWORD = "Use-a-unique-strong-password-123!"
   $env:ADMIN_EMAIL = "owner@example.com"
   ```

   Use your own unique password; do not copy this example. The administrator signs in with the username. `ADMIN_EMAIL` is profile/contact data only and is not used for sign-in or email delivery.
4. Start the server with `npm start`.
5. Open `http://localhost:3000`.

On Windows, SQLite data is stored outside cloud-synced folders by default at `%LOCALAPPDATA%\MYFB Investment\data`. Set `MYFB_DATA_DIR` to override it.

For an existing Windows install, stop the app and copy `data\myfb.db` plus any `myfb.db-wal` and `myfb.db-shm` files together into that local data directory. Keep the original files until the migrated app has been checked.

## Render deployment

Create a Render web service using:

- **Build command:** `npm install`
- **Start command:** `npm start`
- **Health check path:** `/healthz`
- **Persistent disk mount path:** `/var/data`

Set these Render environment variables:

- `NODE_ENV=production`
- `MYFB_DATA_DIR=/var/data`
- `SESSION_SECRET`: a private random value of at least 32 characters
- `ADMIN_USERNAME`: the administrator's username
- `ADMIN_PASSWORD`: a private strong password (12+ characters with uppercase, lowercase, a number, and a symbol)
- `ADMIN_EMAIL`: optional owner contact email shown only to the administrator; it is not used for sign-in or email delivery

The persistent disk is required: Render's ordinary service filesystem is ephemeral, so a SQLite database stored outside the disk can be lost on redeploy. Keep one service instance for this SQLite deployment. Back up the disk regularly.

Existing legacy administrator seed accounts are disabled until `ADMIN_USERNAME` and `ADMIN_PASSWORD` are configured. There are no built-in administrator credentials.

## Accounts and email

- Users sign in with their username and password. Email verification and email-based sign-in are not used.
- Customer passwords require at least 6 characters; longer, unique passwords are recommended. Administrator passwords keep the stronger 12-character mixed-case, number, and symbol requirement.
- The private chat uses clearly identified sender bubbles, room status, message times, and a safety reminder not to share passwords or payment details.
- Email is optional. It is saved only when a user explicitly opts in to advertising emails; consent can be withdrawn from the profile.
- The application does not send account, verification, recovery, or support emails.
- Users can change their password while signed in. Email-based recovery is disabled, so keep the password safe.
- Administrators manage customer conversations under **Chat rooms**. Every customer's room is private to that customer and authorized administrators; administrators can close or reopen rooms.
- Customers can report usernames for review. Administrators can review reports, add notes, and suspend or restore customer accounts. Community rules are editable from **Website settings**.
- Password forms show a live strength guide. The minimum customer password length is 6 characters; administrator credentials use the stricter policy described above.

## SQLite data recovery

Do not delete `myfb.db-wal` or `myfb.db-shm` while the application is stopped; the WAL can contain recent data. Before copying a database, stop every server using it and copy the main database and any sidecars together. The Windows default avoids OneDrive locking by storing SQLite in `%LOCALAPPDATA%`.

## Tests

Run `npm test` for the application, account, chat, and database tests.
