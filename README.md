# ZeroChat

A simple browser-based peer-to-peer chat application.

[Open ZeroChat](https://cxsty.github.io/zerochat/)

## Features

- Trust Rooms
- Temporary usernames
- No accounts
- WebRTC peer-to-peer chat
- Encrypted WebRTC transport
- Cloudflare Worker signaling
- Room and user presence
- Works directly in the browser
- No installation required

## How it works

Users first enter a Trust Room.

A room can be created by one user and joined by another. Both users can chat in the room before starting a secure session.

When both users agree, ZeroChat starts WebRTC negotiation. Once the connection is established, messages are sent through the WebRTC data channel between the two browsers.

```text
User A
   │
   │
   └──────── WebRTC P2P ────────┐
                                │
                                │
                           User B
```

The Cloudflare Worker is used for room management, presence and WebRTC signaling. Normal chat messages are not routed through the Worker after the P2P connection is established.

## Temporary identities

ZeroChat does not use accounts.

A username is associated with a temporary browser identity for up to one hour.

Opening ZeroChat in another browser or resetting the browser session creates a new identity.

## Polling

ZeroChat uses polling for server updates.

Outside a chat, polling checks for active Trust Rooms.

Inside a Trust Room, polling checks room state and handles WebRTC signaling until the P2P connection is established.

The current polling status is shown in the top bar.

Once the P2P connection is established, signaling polling stops.

## Security

WebRTC provides encrypted transport for the peer-to-peer connection.

The Worker handles signaling and room coordination rather than acting as the normal message transport after the P2P connection is established.

ZeroChat has not been independently audited and is still a small experimental project.

## Project structure

```text
ZeroChat/
├── index.html
├── app.js
├── worker.js
├── wrangler.jsonc
└── README.md
```

## Running locally

The frontend is just HTML and JavaScript and does not require Node.js or a build system.

The signaling backend runs as a Cloudflare Worker.

## Limitations

ZeroChat is still under development.

Connection reliability can depend on the users' networks and WebRTC support.

The current identity system is temporary and is not intended to provide strong identity verification.

## Roadmap

- Better identity verification
- Application-level encryption
- Better WebRTC reliability
- Mobile improvements
- Security review

## License

License information will be added later.
