# Desktop tray lifecycle

Status: implemented; local analyze and 220 Dart tests PASS. Windows compilation + 6 actual desktop channel tests passed (44030695768).
The first report does not identify which conditional branch ran. Follow-up
44031775552 passed with explicit available=true, actual hide/restore and DPAPI
preference checked; unavailable fallback was not exercised on that runner. Windows 10/11 desktop acceptance is
separate, including taskbar menu keyboard interaction, DPI and Explorer restart.

The native runner owns one notification icon using the existing LiWeTun resource.
Left click opens the window; right click offers Open / Exit. By default closing
the window exits. An explicit Support-screen switch enables close-to-tray and
saves the preference in the same current-user DPAPI envelope as profiles.
Hiding retains the GUI process and authenticated service lease; an active tunnel
continues. Exit actually closes the process, releasing its lease; the existing
service-side lease-death cleanup remains the independent stop boundary. This
change adds no automatic connection or privileged background process.

The window may hide only if Shell_NotifyIcon successfully registered its icon
and the option was enabled. If registration fails, hide is refused. Explorer's
TaskbarCreated message re-registers the icon; failure restores the window to
keep it reachable. An unavailable native channel reports unknown availability;
no positive tray capability is fabricated. A failed enable is not persisted.

The strict outer private-cache schema v3 adds a boolean close_to_tray and retains
the source-bound subscriptions map, even when empty. v1/v2 caches read as false;
false emits the existing v1/v2 format. Changing this preference preserves
subscriptions, selection, revision floors and entitlement deadlines. Older
clients cannot read v3 and must fail closed rather than overwrite the cache.
Persistence failures use the existing explicit memory-only/blocked storage state.

The closed desktop channel accepts only configure(bool), query, show and hide.
It exposes capability, effective close behavior and window visibility, no paths,
commands, profile data or network settings. The Windows integration fixture
checks real hide/show and DPAPI when a tray is available, otherwise confirms the
window remains visible; it resets the option and cleans only its owned cache.
A conditional runner test is not desktop acceptance of the tray menu.

Deferred: user startup/autoconnect, automatic server selection, a tray connection
status/menu action, and a signed update mechanism. No fabricated Internet state.


The corresponding installer payload passed 14 qualification groups in run
44032587048, with medium-integrity installed GUI/service query, rollback,
visible-window uninstall guard and complete uninstall cleanup. No tunnel start;
only ephemeral CI signing. This is not an owner-installable release package.
