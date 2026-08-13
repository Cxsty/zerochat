# ZeroChat

A simple browser-based peer-to-peer chat application.

ZeroChat lets users create Trust Rooms, chat before establishing a secure session, and then connect directly through WebRTC.

## Support ZeroChat

If you like ZeroChat and want to support the project, donations are appreciated.

**Bitcoin**

`bc1q2jh0asx0sqlhnq269qm77gpq5depmg4r5k2p29`

**Ethereum**

`0xa76b7d71d84f3bD2519C80c80bbca016284A9374`

**Litecoin**

`ltc1q9nc22lhlmurhzc5jnhzvxe2ctkyzxn2nyh8f3j`

**Dogecoin**

`DMohjnUjb8XHsN81AhwC18kLDKjenfGWga`

[Open ZeroChat](https://cxsty.github.io/zerochat/)

## Features

- Trust Rooms
- Temporary usernames
- No accounts
- WebRTC peer-to-peer chat
- Encrypted WebRTC transport
- Cloudflare Worker signaling
- Room and user presence
- Browser-based
- No installation required

## How It Works

Users first enter a Trust Room.

One user creates a room and another user joins it. Both users can chat in the room before starting a secure session.

When both users agree, ZeroChat starts WebRTC negotiation.

```text
User A
   │
   │
   └──────── WebRTC P2P ────────┐
                                │
                                │
                           User B
