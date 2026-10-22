# Slack approvals over Socket Mode

Kronagent posts an approval card for every action that needs a person, and the
buttons on that card approve or deny it. With **Socket Mode** the clicks reach
Kronagent over a WebSocket that Kronagent opens to Slack, so the deployment
needs no public URL and no inbound port.

1. **Create the app.** At <https://api.slack.com/apps>, choose *Create New App*,
   then *From a manifest*, and paste [`manifest.json`](manifest.json). It asks
   for one bot scope, `chat:write`, and turns on interactivity and Socket Mode.
2. **Make an app-level token.** Under *Basic Information*, then *App-Level
   Tokens*, generate a token with the `connections:write` scope. It starts with
   `xapp-`.
3. **Install the app** to the workspace and copy the *Bot User OAuth Token*
   (`xoxb-…`). Invite the bot to the channel the cards should go to.
4. **Configure Kronagent:**

   | Variable | Value |
   |---|---|
   | `KRONAGENT_SLACK_APP_TOKEN` | the `xapp-…` token |
   | `KRONAGENT_SLACK_BOT_TOKEN` | the `xoxb-…` token |
   | `KRONAGENT_SLACK_CHANNEL_ID` | the channel's ID, e.g. `C0123456789` |
   | `KRONAGENT_SLACK_USER_MAPPING` | JSON mapping Slack user IDs to operator IDs, e.g. `{"U0123ABC": "alice"}` |

   Install the extra with `pip install "kronagent[slack]"`, and run
   `kronagent-serve`. Socket Mode starts with it.
5. **Check it:** `kronagent-preflight` reports *Approvals in Slack*.

**Who may click.** Socket Mode removes the signing-secret check, because only
Slack can open the socket. It doesn't change who may act: with an operator
registry (`KRONAGENT_OPERATOR_REGISTRY`), a click is accepted only from a mapped,
active operator with approval rights for that tenant, exactly as on the HTTP
route. **Without a registry, anyone in the channel can approve.** Use a
registry for any real deployment.

The tokens are secrets. In the AWS stack they go in Secrets Manager, never in a
file or a template parameter's default.
