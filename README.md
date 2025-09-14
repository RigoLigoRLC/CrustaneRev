
# CrustaneRev

Crustane died after a great massacre of QQ bots. Now we're back with official QQ bot APIs.

## Usage

Build with an arbitrary version of Rust and run.

Several environments are required.

| Environment Variable | What to write                                                                                                                                                                                                                                                                        |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CRUSTANEREV_CURENV   | A codename for your current running environment (like, "Dev", "Prod", etc)<br/>This is mostly just for display when user invokes a command that displays bot status                                                                                                                  |
| CRUSTANEREV_DATA_DIR | CrustaneRev's data storage directory. CrustaneRev may serve images to users, store user-submitted data, and maintain a database.<br/>You should back it up periodically.<br/>If the directory is nonexistent or empty, CrustaneRev will initialize it before summoning bot instance. |
| QQ_BOT_APP_ID        | AppID from QQ bot profile page.                                                                                                                                                                                                                                                      |
| QQ_BOT_SECRET        | Secret from QQ bot profile page. This is needed for authentication.                                                                                                                                                                                                                  |

Normally you run the program without any arguments. You may specify one single command argument for some special operations. These are described below:

- `totp_qr`
  
  CrustaneRev contains a shared-secret TOTP-based admin authentication utility. If you want to, for example, nuke the database with a single command sent to the bot in a public chat, you may utilize this feature to make sure nobody else can do the same.

  When launching CrustaneRev with this command argument, you'll get a QR Code in terminal, generated based on hashed bot secret, and you can scan the QR code with apps like Google Authenticator to get a TOTP challenge code that can be used later for verifying administrator identity.

# License

CrustaneRev (The software) is distributed under GNU AGPL 3.0 License.
