# Status pages

A status page shows chosen hosts and checks to people who have no account. Create one under **Status pages** in the UI.

- **Title and URL slug**: the page is served at `/status/<slug>`.
- **Public**: on, anyone with the link can view it. Off, only people with the secret link (it carries a token) can.
- **Items**: pick hosts and checks and give each a display label. Only labels and statuses are published, never hostnames or addresses. Metrics are published only where you turn them on (see below).
- **90-day history**: optionally show daily uptime for each item.
- **Announcement banner**: optional text, for example a maintenance notice.

## Optional extras

A page that uses none of these looks and behaves as before.

- **Icon**: choose one of the built-in icons or upload an image (PNG, JPEG, WebP or SVG, under 500 KB). With no icon the page shows the logo from Branding.
- **Host metrics**: under each host item, choose any of CPU, Memory, Network and Disk, or **All**. The page then shows ring gauges for CPU, memory and disk and the last hour of network traffic for that host.
- **Add all hosts with all metrics**: adds every host that is not on the page yet and turns all metrics on for every host. **Add all hosts** adds them without metrics.
- **Theme**: Light or Dark fixes the page's theme for everyone, whatever theme they use in the app. Viewer's choice follows each viewer's own setting. `?theme=dark` or `?theme=light` on a link overrides it for that link.
- **Add all checks**: adds every check that is not on the page yet.
- **Overview graphs**: graphs of CPU, memory and network over the last hour with a line for every host on the page. Hover a graph to read each host's value at that time. CPU and memory zoom to the range the hosts cover, and network uses a logarithmic scale, so the lines spread out instead of bunching together; each graph labels both ends of its scale.
- **Wall display**: a full-width layout with a tile per item, a clock, and how many hosts and checks are up in the header. Hosts that show metrics come first, then the other items.

A host or check that is down and whose alert is acknowledged as **expected** is shown as "Off (expected)". It does not turn the page's overall state to an outage.

Pages that show metrics, the overview or the wall display refresh every 15 seconds; other pages every 60.

Metrics and the overview are visible to anyone who can open the page. For a page that should not be public, turn **Public** off and use the secret link.

The data endpoint for public pages is described in the [API](api.md#public-status-pages).
