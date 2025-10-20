# TinyPilot REST Input API

TinyPilot now exposes REST endpoints that allow authenticated clients to send
keyboard and mouse input over HTTP. This enables scripting scenarios, such as
controlling a TinyPilot from another machine on the same LAN.

## Authentication

All endpoints require an authenticated session with at least operator
privileges. Authenticate by POSTing JSON credentials to `/api/auth` and store
the returned session cookie:

```bash
curl \
  --cookie-jar tinypilot-session.txt \
  --header 'Content-Type: application/json' \
  --request POST \
  --data '{"username": "operator", "password": "example"}' \
  http://tinypilot.local/api/auth
```

Reuse the cookie jar for subsequent requests (for example with
`--cookie tinypilot-session.txt`).

## Keyboard input

### Single keystrokes

**Endpoints**: `POST /api/hid/keyboard`, `POST /api/hid/keyboard/press`

**Purpose**: Sends a single key press, optionally with modifier keys.

**Request body**:

```json
{
  "code": "KeyA",
  "key": "a",
  "ctrlLeft": false,
  "altLeft": false,
  "shiftLeft": false
}
```

`code` is the only required property and must match a key defined in
`app/js_to_hid.py`. All modifier flags default to `false` if omitted. The
`key` field is optional and used only for logging.

**Response**: `200 OK` on success. Errors return a JSON payload with a
descriptive message and `4xx/5xx` status code.

### Holding and releasing keys

**Hold endpoint**: `POST /api/hid/keyboard/hold`

**Release endpoint**: `POST /api/hid/keyboard/release`

- A hold request uses the same payload as the single keystroke endpoint. TinyPilot
  keeps the key (and modifiers) pressed until a matching release request arrives
  or you release everything.
- To release a specific key, provide `{ "code": "KeyA" }` in the request body.
- To release **all** held keys, send an empty JSON object (or omit the body).

Holding modifiers and non-modifier keys together respects USB HID limits; you
can hold up to six non-modifier keys at once.

## Mouse input

**Endpoint**: `POST /api/hid/mouse`

**Purpose**: Sends a mouse event, including button state, movement, and scroll
wheel deltas.

**Request body**:

```json
{
  "buttons": 1,
  "relativeX": 0.42,
  "relativeY": 0.73,
  "verticalWheelDelta": 0,
  "horizontalWheelDelta": 0
}
```

- `buttons` is a bitmask representing the pressed mouse buttons.
- `relativeX` and `relativeY` are floats between 0.0 and 1.0 describing the
  cursor position.
- Wheel deltas must be `-1`, `0`, or `1`.

**Response**: `200 OK` on success with an empty JSON object.

### Mouse button control

- `POST /api/hid/mouse/press` – Presses the specified button bitmask and
  releases it immediately after the event completes. Useful for clicks.
- `POST /api/hid/mouse/hold` – Keeps the specified buttons pressed until you
  explicitly release them. Combine with cursor moves or scroll deltas by
  including `relativeX`, `relativeY`, `verticalWheelDelta`, or
  `horizontalWheelDelta` in the body.
- `POST /api/hid/mouse/release` – Releases buttons. Omit the `buttons` field to
  release everything currently held, or provide a bitmask to release specific
  buttons.

Each endpoint accepts the same optional movement and scroll properties as
`/api/hid/mouse`. For example, this request clicks the left button without
moving the cursor:

```bash
curl \
  --cookie tinypilot-session.txt \
  --header 'Content-Type: application/json' \
  --request POST \
  --data '{"buttons": 1}' \
  http://tinypilot.local/api/hid/mouse/press
```

### Absolute cursor positioning

**Endpoint**: `POST /api/hid/cursor`

**Purpose**: Moves the cursor to a specific pixel location while optionally
pressing buttons or scrolling.

**Request body**:

```json
{
  "x": 960,
  "y": 540,
  "screenWidth": 1920,
  "screenHeight": 1080,
  "buttons": 0,
  "verticalWheelDelta": 0,
  "horizontalWheelDelta": 0
}
```

`x`/`y` are absolute coordinates and TinyPilot translates them into the
relative range the HID interface expects. Coordinates outside the boundaries
are clamped to the edges of the screen.

## Paste text

**Endpoint**: `POST /api/hid/paste`

**Purpose**: Sends an entire string to the controlled machine by simulating the
equivalent keystrokes.

**Request body**:

```json
{
  "text": "Hello from REST!",
  "language": "en-US"
}
```

- `text` is required and contains the characters to type.
- `language` is optional and defaults to `en-US` when omitted. It determines
  how TinyPilot translates characters into HID keycodes.

Unsupported characters yield a `400` response listing the problematic glyphs.

## Macros

**Endpoint**: `POST /api/hid/macro`

**Purpose**: Replays a sequence of keyboard and mouse events with optional
delays between each step.

**Request body**:

```json
{
  "events": [
    {
      "type": "keyboard",
      "code": "ShiftLeft"
    },
    {
      "type": "keyboard",
      "code": "KeyA",
      "delayMs": 150
    },
    {
      "type": "mouse",
      "buttons": 1,
      "relativeX": 0.5,
      "relativeY": 0.5,
      "delayMs": 250
    },
    {
      "type": "delay",
      "ms": 500
    }
  ]
}
```

- `type` is required for every event and can be `keyboard`, `mouse`, or `delay`.
- `keyboard`/`keyboardPress` events share the same fields as the single
  keystroke endpoint plus an optional `delayMs` that applies after the
  keystroke.
- `keyboardHold` maintains the key state until a subsequent `keyboardRelease`
  (which can optionally include a `code` to release a specific key, or omit it
  to release all held keys).
- `mouse`/`mouseMove` events accept the same payload as `/api/hid/mouse`, also
  with an optional `delayMs`.
- `mouseHold`, `mousePress`, and `mouseRelease` mirror the dedicated mouse
  endpoints described above. `mouseRelease` releases all buttons when the
  `buttons` field is omitted.
- `delay` events require an `ms` field and pause the macro before continuing.

TinyPilot executes the macro asynchronously, so the HTTP response returns
immediately after scheduling the sequence.

## Key and mouse capabilities

- **Endpoint**: `GET /api/hid/keymap`

  Returns the available keyboard codes, the corresponding HID values, and
  TinyPilot’s limit on simultaneous non-modifier keys.

- **Endpoint**: `GET /api/hid/mouse-info`

  Returns the maximum supported mouse buttons, wheel delta values, and the
  relative coordinate range enforced by TinyPilot.

## Quick Python example

The snippet below illustrates sending the letter `A` and a left-click using the
Python `requests` library after obtaining an authenticated session:

```python
import requests

session = requests.Session()
session.post(
    "http://tinypilot.local/api/auth",
    json={"username": "operator", "password": "example"},
)

session.post(
    "http://tinypilot.local/api/hid/keyboard",
    json={"code": "KeyA", "key": "a", "shiftLeft": True},
)

session.post(
    "http://tinypilot.local/api/hid/keyboard/hold",
    json={"code": "ShiftLeft"},
)

session.post(
    "http://tinypilot.local/api/hid/keyboard",
    json={"code": "KeyB", "key": "b"},
)

session.post(
    "http://tinypilot.local/api/hid/keyboard/release",
    json={"code": "ShiftLeft"},
)

session.post(
    "http://tinypilot.local/api/hid/mouse",
    json={
        "buttons": 1,
        "relativeX": 0.5,
        "relativeY": 0.5,
        "verticalWheelDelta": 0,
        "horizontalWheelDelta": 0,
    },
)

session.post(
    "http://tinypilot.local/api/hid/mouse/press",
    json={"buttons": 1},
)

session.post(
    "http://tinypilot.local/api/hid/paste",
    json={"text": "Hello from REST!", "language": "en-US"},
)

session.post(
    "http://tinypilot.local/api/hid/macro",
    json={
        "events": [
            {"type": "keyboard", "code": "KeyC"},
            {"type": "delay", "ms": 200},
            {"type": "keyboard", "code": "KeyD", "ctrlLeft": True},
            {"type": "mousePress", "buttons": 1}
        ]
    },
)
```

The example assumes TinyPilot is reachable at `http://tinypilot.local/`. Adjust
the hostname or IP address to match your environment.
