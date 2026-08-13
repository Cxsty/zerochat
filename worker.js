import { DurableObject } from "cloudflare:workers";

const ROOM_TIMEOUT = 60 * 60 * 1000;
const USER_TIMEOUT = 2 * 60 * 1000;
const GUEST_LEAVE_TIMEOUT = 5000;
const IDENTITY_TIMEOUT = 60 * 60 * 1000;

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        }
    });
}

async function readJSON(request) {
    return request.json().catch(() => ({}));
}

export class ZeroChat extends DurableObject {
    constructor(ctx, env) {
        super(ctx, env);

        this.ctx.blockConcurrencyWhile(async () => {
            this.ctx.storage.sql.exec(`
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    last_seen INTEGER NOT NULL,
                    identity_fingerprint TEXT,
                    identity_data TEXT,
                    identity_expires INTEGER
                );

                CREATE TABLE IF NOT EXISTS rooms (
                    id TEXT PRIMARY KEY,
                    host TEXT NOT NULL,
                    guest TEXT,
                    created INTEGER NOT NULL,
                    empty_since INTEGER
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    message TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS secure (
                    room_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    accepted INTEGER NOT NULL,
                    PRIMARY KEY (room_id, username)
                );

                CREATE TABLE IF NOT EXISTS signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    data TEXT NOT NULL
                );
            `);

            const columns = this.ctx.storage.sql
                .exec(`PRAGMA table_info(users)`)
                .toArray()
                .map(column => column.name);

            if (!columns.includes("identity_fingerprint")) {
                this.ctx.storage.sql.exec(
                    `ALTER TABLE users ADD COLUMN identity_fingerprint TEXT`
                );
            }

            if (!columns.includes("identity_data")) {
                this.ctx.storage.sql.exec(
                    `ALTER TABLE users ADD COLUMN identity_data TEXT`
                );
            }

            if (!columns.includes("identity_expires")) {
                this.ctx.storage.sql.exec(
                    `ALTER TABLE users ADD COLUMN identity_expires INTEGER`
                );
            }
        });
    }

    cleanup() {
        const now = Date.now();

        const inactiveUsers = this.ctx.storage.sql
            .exec(
                `SELECT username
                 FROM users
                 WHERE last_seen < ?`,
                now - USER_TIMEOUT
            )
            .toArray();

        for (const user of inactiveUsers) {
            const rooms = this.ctx.storage.sql
                .exec(
                    `SELECT id
                     FROM rooms
                     WHERE host = ? OR guest = ?`,
                    user.username,
                    user.username
                )
                .toArray();

            for (const room of rooms) {
                this.deleteRoom(room.id);
            }

            this.ctx.storage.sql.exec(
                `DELETE FROM signals WHERE target = ?`,
                user.username
            );

            this.ctx.storage.sql.exec(
                `DELETE FROM users WHERE username = ?`,
                user.username
            );
        }

        this.ctx.storage.sql.exec(
            `UPDATE users
             SET identity_fingerprint = NULL,
                 identity_data = NULL,
                 identity_expires = NULL
             WHERE identity_expires IS NOT NULL
             AND identity_expires < ?`,
            now
        );

        const oldRooms = this.ctx.storage.sql
            .exec(
                `SELECT id
                 FROM rooms
                 WHERE created < ?`,
                now - ROOM_TIMEOUT
            )
            .toArray();

        for (const room of oldRooms) {
            this.deleteRoom(room.id);
        }

        const abandonedRooms = this.ctx.storage.sql
            .exec(
                `SELECT id
                 FROM rooms
                 WHERE empty_since IS NOT NULL
                 AND empty_since < ?`,
                now - GUEST_LEAVE_TIMEOUT
            )
            .toArray();

        for (const room of abandonedRooms) {
            this.deleteRoom(room.id);
        }
    }

    deleteRoom(roomId) {
        this.ctx.storage.sql.exec(
            `DELETE FROM messages WHERE room_id = ?`,
            roomId
        );

        this.ctx.storage.sql.exec(
            `DELETE FROM secure WHERE room_id = ?`,
            roomId
        );

        this.ctx.storage.sql.exec(
            `DELETE FROM signals
             WHERE data LIKE ?`,
            `%"room":"${roomId}"%`
        );

        this.ctx.storage.sql.exec(
            `DELETE FROM rooms WHERE id = ?`,
            roomId
        );
    }

    userInRoom(username) {
        const result = this.ctx.storage.sql
            .exec(
                `SELECT id
                 FROM rooms
                 WHERE host = ? OR guest = ?
                 LIMIT 1`,
                username,
                username
            )
            .toArray();

        return result.length > 0;
    }

    async fetch(request) {
        const url = new URL(request.url);

        this.cleanup();

        if (request.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            });
        }

        const path = url.pathname;

        if (path === "/join" && request.method === "POST") {
            const data = await readJSON(request);
            const username = String(data.username || "").trim();
            const identity = data.identity || {};

            if (!username || username.length > 32) {
                return json({
                    ok: false,
                    error: "invalid_username"
                }, 400);
            }

            if (
                !identity.fingerprint ||
                !identity.signingPublicKey ||
                !identity.encryptionPublicKey ||
                !identity.expiresAt
            ) {
                return json({
                    ok: false,
                    error: "missing_identity"
                }, 400);
            }

            const now = Date.now();

            if (Number(identity.expiresAt) <= now) {
                return json({
                    ok: false,
                    error: "identity_expired"
                }, 400);
            }

            const existing = this.ctx.storage.sql
                .exec(
                    `SELECT username,
                            last_seen,
                            identity_fingerprint,
                            identity_data,
                            identity_expires
                     FROM users
                     WHERE username = ?`,
                    username
                )
                .toArray();

            if (existing.length > 0) {
                const user = existing[0];

                const identityStillValid =
                    user.identity_fingerprint &&
                    user.identity_expires &&
                    user.identity_expires > now;

                if (
                    identityStillValid &&
                    user.identity_fingerprint !== identity.fingerprint
                ) {
                    return json({
                        ok: false,
                        error: "identity_conflict"
                    }, 409);
                }

                this.ctx.storage.sql.exec(
                    `UPDATE users
                     SET last_seen = ?,
                         identity_fingerprint = ?,
                         identity_data = ?,
                         identity_expires = ?
                     WHERE username = ?`,
                    now,
                    identity.fingerprint,
                    JSON.stringify({
                        fingerprint: identity.fingerprint,
                        signingPublicKey: identity.signingPublicKey,
                        encryptionPublicKey: identity.encryptionPublicKey
                    }),
                    Math.min(
                        Number(identity.expiresAt),
                        now + IDENTITY_TIMEOUT
                    ),
                    username
                );
            } else {
                this.ctx.storage.sql.exec(
                    `INSERT INTO users
                     (username, last_seen, identity_fingerprint, identity_data, identity_expires)
                     VALUES (?, ?, ?, ?, ?)`,
                    username,
                    now,
                    identity.fingerprint,
                    JSON.stringify({
                        fingerprint: identity.fingerprint,
                        signingPublicKey: identity.signingPublicKey,
                        encryptionPublicKey: identity.encryptionPublicKey
                    }),
                    Math.min(
                        Number(identity.expiresAt),
                        now + IDENTITY_TIMEOUT
                    )
                );
            }

            return json({
                ok: true,
                identity: {
                    fingerprint: identity.fingerprint,
                    expiresAt: Math.min(
                        Number(identity.expiresAt),
                        now + IDENTITY_TIMEOUT
                    )
                }
            });
        }

        if (path === "/users" && request.method === "GET") {
            const result = this.ctx.storage.sql
                .exec(
                    `SELECT username
                     FROM users
                     ORDER BY username`
                )
                .toArray();

            return json({
                users: result.map(row => row.username)
            });
        }

        if (path === "/room/create" && request.method === "POST") {
            const data = await readJSON(request);
            const username = String(data.username || "").trim();

            const user = this.ctx.storage.sql
                .exec(
                    `SELECT username
                     FROM users
                     WHERE username = ?`,
                    username
                )
                .toArray();

            if (user.length === 0) {
                return json({
                    ok: false,
                    error: "not_joined"
                });
            }

            if (this.userInRoom(username)) {
                return json({
                    ok: false,
                    error: "already_in_room"
                });
            }

            const roomId = crypto.randomUUID().replaceAll("-", "");

            this.ctx.storage.sql.exec(
                `INSERT INTO rooms
                 (id, host, guest, created, empty_since)
                 VALUES (?, ?, NULL, ?, NULL)`,
                roomId,
                username,
                Date.now()
            );

            return json({
                ok: true,
                room: roomId
            });
        }

        if (path === "/rooms" && request.method === "GET") {
            const result = this.ctx.storage.sql
                .exec(
                    `SELECT id, host
                     FROM rooms
                     WHERE guest IS NULL
                     ORDER BY created`
                )
                .toArray();

            return json({
                rooms: result.map(room => ({
                    room: room.id,
                    host: room.host
                }))
            });
        }

        if (path === "/room/join" && request.method === "POST") {
            const data = await readJSON(request);

            const username = String(data.username || "").trim();
            const roomId = String(data.room || "");

            const user = this.ctx.storage.sql
                .exec(
                    `SELECT username
                     FROM users
                     WHERE username = ?`,
                    username
                )
                .toArray();

            if (user.length === 0) {
                return json({
                    ok: false,
                    error: "not_joined"
                });
            }

            const roomResult = this.ctx.storage.sql
                .exec(
                    `SELECT id, host, guest, empty_since
                     FROM rooms
                     WHERE id = ?`,
                    roomId
                )
                .toArray();

            if (roomResult.length === 0) {
                return json({
                    ok: false,
                    error: "room_not_found"
                });
            }

            if (this.userInRoom(username)) {
                return json({
                    ok: false,
                    error: "already_in_room"
                });
            }

            const room = roomResult[0];

            if (room.guest !== null) {
                return json({
                    ok: false,
                    error: "room_full"
                });
            }

            if (room.host === username) {
                return json({
                    ok: false,
                    error: "invalid_join"
                });
            }

            this.ctx.storage.sql.exec(
                `UPDATE rooms
                 SET guest = ?, empty_since = NULL
                 WHERE id = ?`,
                username,
                roomId
            );

            return json({
                ok: true,
                host: room.host,
                guest: username
            });
        }

        if (path === "/room" && request.method === "GET") {
            const roomId = url.searchParams.get("room");

            if (!roomId) {
                return json({
                    ok: false,
                    error: "missing_room"
                }, 400);
            }

            const roomResult = this.ctx.storage.sql
                .exec(
                    `SELECT id, host, guest, empty_since
                     FROM rooms
                     WHERE id = ?`,
                    roomId
                )
                .toArray();

            if (roomResult.length === 0) {
                return json({
                    ok: false
                }, 404);
            }

            const room = roomResult[0];

            const roomMessages = this.ctx.storage.sql
                .exec(
                    `SELECT username, message
                     FROM messages
                     WHERE room_id = ?
                     ORDER BY id`,
                    roomId
                )
                .toArray();

            const secureRows = this.ctx.storage.sql
                .exec(
                    `SELECT username, accepted
                     FROM secure
                     WHERE room_id = ?`,
                    roomId
                )
                .toArray();

            const secure = {};

            for (const row of secureRows) {
                secure[row.username] = row.accepted === 1;
            }

            const deleteAt = room.empty_since
                ? room.empty_since + GUEST_LEAVE_TIMEOUT
                : null;

            return json({
                ok: true,
                host: room.host,
                guest: room.guest,
                messages: roomMessages,
                secure,
                delete_at: deleteAt
            });
        }

        if (path === "/room/message" && request.method === "POST") {
            const data = await readJSON(request);

            const roomId = String(data.room || "");
            const username = String(data.username || "");
            const message = String(data.message || "").trim();

            if (!message || message.length > 4000) {
                return json({
                    ok: false,
                    error: "invalid_message"
                }, 400);
            }

            const roomResult = this.ctx.storage.sql
                .exec(
                    `SELECT host, guest
                     FROM rooms
                     WHERE id = ?`,
                    roomId
                )
                .toArray();

            if (roomResult.length === 0) {
                return json({
                    ok: false,
                    error: "room_not_found"
                });
            }

            const room = roomResult[0];

            if (
                username !== room.host &&
                username !== room.guest
            ) {
                return json({
                    ok: false,
                    error: "not_in_room"
                });
            }

            this.ctx.storage.sql.exec(
                `INSERT INTO messages
                 (room_id, username, message)
                 VALUES (?, ?, ?)`,
                roomId,
                username,
                message
            );

            return json({ ok: true });
        }

        if (path === "/room/secure" && request.method === "POST") {
            const data = await readJSON(request);

            const roomId = String(data.room || "");
            const username = String(data.username || "");
            const accept = Boolean(data.accept);

            const roomResult = this.ctx.storage.sql
                .exec(
                    `SELECT host, guest
                     FROM rooms
                     WHERE id = ?`,
                    roomId
                )
                .toArray();

            if (roomResult.length === 0) {
                return json({
                    ok: false,
                    error: "room_not_found"
                });
            }

            const room = roomResult[0];

            if (
                username !== room.host &&
                username !== room.guest
            ) {
                return json({
                    ok: false,
                    error: "not_in_room"
                });
            }

            this.ctx.storage.sql.exec(
                `INSERT INTO secure
                 (room_id, username, accepted)
                 VALUES (?, ?, ?)
                 ON CONFLICT(room_id, username)
                 DO UPDATE SET accepted = excluded.accepted`,
                roomId,
                username,
                accept ? 1 : 0
            );

            return json({
                ok: true,
                username,
                accept
            });
        }

        if (path === "/room/leave" && request.method === "POST") {
            const data = await readJSON(request);

            const roomId = String(data.room || "");
            const username = String(data.username || "");

            const roomResult = this.ctx.storage.sql
                .exec(
                    `SELECT host, guest
                     FROM rooms
                     WHERE id = ?`,
                    roomId
                )
                .toArray();

            if (roomResult.length === 0) {
                return json({ ok: true });
            }

            const room = roomResult[0];

            if (
                username !== room.host &&
                username !== room.guest
            ) {
                return json({
                    ok: false,
                    error: "not_in_room"
                });
            }

            if (username === room.host) {
                this.deleteRoom(roomId);

                return json({
                    ok: true,
                    deleted: true
                });
            }

            this.ctx.storage.sql.exec(
                `INSERT INTO messages
                 (room_id, username, message)
                 VALUES (?, 'system', ?)`,
                roomId,
                `${username} has left the room. The room will be deleted in 5 seconds if nobody remains.`
            );

            this.ctx.storage.sql.exec(
                `UPDATE rooms
                 SET guest = NULL,
                     empty_since = ?
                 WHERE id = ?`,
                Date.now(),
                roomId
            );

            this.ctx.storage.sql.exec(
                `DELETE FROM secure
                 WHERE room_id = ?`,
                roomId
            );

            return json({ ok: true });
        }

        if (path === "/signal" && request.method === "POST") {
            const data = await readJSON(request);

            const target = String(data.target || "");

            if (!target) {
                return json({
                    ok: false,
                    error: "missing_target"
                }, 400);
            }

            const user = this.ctx.storage.sql
                .exec(
                    `SELECT username
                     FROM users
                     WHERE username = ?`,
                    target
                )
                .toArray();

            if (user.length === 0) {
                return json({
                    ok: false,
                    error: "target_not_found"
                });
            }

            this.ctx.storage.sql.exec(
                `INSERT INTO signals
                 (target, data)
                 VALUES (?, ?)`,
                target,
                JSON.stringify(data)
            );

            return json({ ok: true });
        }

        if (path === "/signals" && request.method === "GET") {
            const username = url.searchParams.get("username");

            if (!username) {
                return json({
                    signals: []
                });
            }

            this.ctx.storage.sql.exec(
                `UPDATE users
                 SET last_seen = ?
                 WHERE username = ?`,
                Date.now(),
                username
            );

            const rows = this.ctx.storage.sql
                .exec(
                    `SELECT id, data
                     FROM signals
                     WHERE target = ?
                     ORDER BY id`,
                    username
                )
                .toArray();

            const signals = rows.map(row => JSON.parse(row.data));

            this.ctx.storage.sql.exec(
                `DELETE FROM signals
                 WHERE target = ?`,
                username
            );

            return json({ signals });
        }

        if (path === "/") {
            return new Response("ZeroChat server online.", {
                status: 200,
                headers: {
                    "Content-Type": "text/plain"
                }
            });
        }

        return json({
            ok: false,
            error: "not_found"
        }, 404);
    }
}

export default {
    async fetch(request, env) {
        const id = env.ZEROCHAT.idFromName("global");
        const stub = env.ZEROCHAT.get(id);

        return stub.fetch(request);
    }
};
