const API = "https://zerochat.loghinconstantin781.workers.dev";

const login = document.getElementById("login");
const users = document.getElementById("users");
const chat = document.getElementById("chat");

const usernameInput = document.getElementById("username");
const enterButton = document.getElementById("enter");
const status = document.getElementById("status");
const pollingStatus = document.getElementById("polling");
const userList = document.getElementById("userList");
const refreshRoomsButton = document.getElementById("refreshRooms");

const chatUser = document.getElementById("chatUser");
const messages = document.getElementById("messages");

const messageInput = document.getElementById("message");
const sendButton = document.getElementById("send");

const backButton = document.getElementById("back");
const secureButton = document.getElementById("secure");

const rtcConfig = {
    iceServers: [
        {
            urls: "stun:stun.l.google.com:19302"
        }
    ]
};

const IDENTITY_DB = "zerochat_identity";
const IDENTITY_STORE = "identity";
const IDENTITY_KEY = "current";
const IDENTITY_LIFETIME = 60 * 60 * 1000;

const ROOM_POLL_INTERVAL = 3000;
const SIGNAL_POLL_INTERVAL = 500;

let username = "";
let currentRoom = "";
let roomPartner = "";

let identity = null;

let peer = null;
let channel = null;

let roomPoll = null;
let signalPoll = null;
let pollingCountdownTimer = null;
let pollingCountdown = 3;

let renderedRoomMessages = 0;
let secureConnectionMessageShown = false;
let roomClosingMessageShown = false;
let secureConnected = false;
let pendingIceCandidates = [];

enterButton.addEventListener("click", enterZeroChat);

usernameInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        enterZeroChat();
    }
});

refreshRoomsButton.addEventListener("click", updateLobby);

sendButton.addEventListener("click", sendRoomMessage);

messageInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        sendRoomMessage();
    }
});

secureButton.addEventListener("click", acceptSecureChat);
backButton.addEventListener("click", leaveRoom);

async function request(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    });

    const data = await response.json();

    if (!response.ok || data.ok === false) {
        throw new Error(data.error || `Request failed: ${response.status}`);
    }

    return data;
}

function openIdentityDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(IDENTITY_DB, 1);

        request.onupgradeneeded = () => {
            if (!request.result.objectStoreNames.contains(IDENTITY_STORE)) {
                request.result.createObjectStore(IDENTITY_STORE);
            }
        };

        request.onsuccess = () => {
            const db = request.result;

            db.onversionchange = () => {
                db.close();
            };

            resolve(db);
        };

        request.onerror = () => {
            reject(request.error);
        };
    });
}

async function getStoredIdentity() {
    const db = await openIdentityDB();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction(IDENTITY_STORE, "readonly");
        const store = transaction.objectStore(IDENTITY_STORE);
        const request = store.get(IDENTITY_KEY);

        request.onsuccess = () => {
            const value = request.result;

            db.close();

            if (!value || value.expiresAt <= Date.now()) {
                if (value) {
                    deleteStoredIdentity().catch(console.error);
                }

                resolve(null);
                return;
            }

            resolve(value);
        };

        request.onerror = () => {
            db.close();
            reject(request.error);
        };
    });
}

async function saveStoredIdentity(value) {
    const db = await openIdentityDB();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction(IDENTITY_STORE, "readwrite");
        const store = transaction.objectStore(IDENTITY_STORE);

        store.put(value, IDENTITY_KEY);

        transaction.oncomplete = () => {
            db.close();
            resolve();
        };

        transaction.onerror = () => {
            db.close();
            reject(transaction.error);
        };
    });
}

async function deleteStoredIdentity() {
    const db = await openIdentityDB();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction(IDENTITY_STORE, "readwrite");
        const store = transaction.objectStore(IDENTITY_STORE);

        store.delete(IDENTITY_KEY);

        transaction.oncomplete = () => {
            db.close();
            resolve();
        };

        transaction.onerror = () => {
            db.close();
            reject(transaction.error);
        };
    });
}

async function fingerprintPublicKey(publicKey) {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    const hash = await crypto.subtle.digest("SHA-256", exported);

    return Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function createIdentity() {
    const signingPair = await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
    );

    const encryptionPair = await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        ["deriveKey"]
    );

    const signingPublicKey = await crypto.subtle.exportKey(
        "jwk",
        signingPair.publicKey
    );

    const signingPrivateKey = await crypto.subtle.exportKey(
        "jwk",
        signingPair.privateKey
    );

    const encryptionPublicKey = await crypto.subtle.exportKey(
        "jwk",
        encryptionPair.publicKey
    );

    const encryptionPrivateKey = await crypto.subtle.exportKey(
        "jwk",
        encryptionPair.privateKey
    );

    const fingerprint = await fingerprintPublicKey(signingPair.publicKey);

    return {
        createdAt: Date.now(),
        expiresAt: Date.now() + IDENTITY_LIFETIME,
        fingerprint,
        signingPublicKey,
        signingPrivateKey,
        encryptionPublicKey,
        encryptionPrivateKey
    };
}

async function loadIdentity() {
    let stored = await getStoredIdentity();

    if (stored) {
        return stored;
    }

    stored = await createIdentity();
    await saveStoredIdentity(stored);

    return stored;
}

function showIdentityNotice() {
    const existing = document.getElementById("identityNotice");

    if (existing) {
        existing.remove();
    }

    const notice = document.createElement("div");

    notice.id = "identityNotice";
    notice.style.marginTop = "10px";
    notice.style.fontSize = "12px";
    notice.style.color = "#777";
    notice.style.lineHeight = "1.5";

    notice.textContent =
        `Your cryptographic identity is saved in this browser for 1 hour. ` +
        `Refreshing or reopening this browser keeps it. Resetting site data ` +
        `or using another browser creates a new identity.`;

    login.appendChild(notice);
}

function setPollingStatus(value) {
    pollingStatus.textContent = value;
}

function stopPollingCountdown() {
    if (pollingCountdownTimer) {
        clearTimeout(pollingCountdownTimer);
        pollingCountdownTimer = null;
    }

    pollingCountdown = 3;
    setPollingStatus("Polling: Off");
}

function startPollingCountdown() {
    if (!currentRoom || secureConnected) {
        stopPollingCountdown();
        return;
    }

    if (pollingCountdownTimer) {
        clearTimeout(pollingCountdownTimer);
    }

    pollingCountdown = 3;
    setPollingStatus("Polling: 3");

    const tick = () => {
        if (!currentRoom || secureConnected) {
            stopPollingCountdown();
            return;
        }

        pollingCountdown--;

        if (pollingCountdown <= 0) {
            pollingCountdownTimer = null;
            setPollingStatus("Polling: 0");
            pollRoom();
            return;
        }

        setPollingStatus(`Polling: ${pollingCountdown}`);

        pollingCountdownTimer = setTimeout(tick, 1000);
    };

    pollingCountdownTimer = setTimeout(tick, 1000);
}

async function enterZeroChat() {
    const name = usernameInput.value.trim();

    if (!name) {
        return;
    }

    username = name;

    try {
        identity = await loadIdentity();

        const identityData = await request("/join", {
            method: "POST",
            body: JSON.stringify({
                username,
                identity: {
                    fingerprint: identity.fingerprint,
                    signingPublicKey: identity.signingPublicKey,
                    encryptionPublicKey: identity.encryptionPublicKey,
                    expiresAt: identity.expiresAt
                }
            })
        });

        if (
            identityData.identity &&
            identityData.identity.fingerprint &&
            identityData.identity.fingerprint !== identity.fingerprint
        ) {
            await deleteStoredIdentity();
            identity = await loadIdentity();

            await request("/join", {
                method: "POST",
                body: JSON.stringify({
                    username,
                    identity: {
                        fingerprint: identity.fingerprint,
                        signingPublicKey: identity.signingPublicKey,
                        encryptionPublicKey: identity.encryptionPublicKey,
                        expiresAt: identity.expiresAt
                    }
                })
            });
        }

        login.hidden = true;
        users.hidden = false;

        setOnline(true);
        stopPollingCountdown();

        await updateLobby();
    } catch (error) {
        console.error(error);

        setOnline(false);

        if (error.message === "identity_conflict") {
            alert(
                "This username is already associated with another active identity. " +
                "Use the original browser or choose another username."
            );
        } else {
            alert("Could not connect to ZeroChat server.");
        }
    }
}

function setOnline(value) {
    status.textContent = value ? "Online" : "Offline";
    status.classList.toggle("online", value);
}

async function updateLobby() {
    if (!username || currentRoom) {
        return;
    }

    stopPollingCountdown();

    try {
        const data = await request("/rooms");

        showRooms(Array.isArray(data.rooms) ? data.rooms : []);
        setOnline(true);
    } catch (error) {
        console.error(error);
        setOnline(false);
    }
}

function showRooms(roomList) {
    userList.innerHTML = "";

    if (roomList.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No Trust Rooms available.";
        userList.appendChild(empty);
    }

    for (const room of roomList) {
        const element = document.createElement("div");
        element.className = "user";

        if (room.host === username) {
            element.textContent = `${room.host} — Your room`;
            element.style.color = "#777";
            element.style.cursor = "default";
        } else {
            element.textContent = room.host;
            element.addEventListener("click", () => joinRoom(room.room));
        }

        userList.appendChild(element);
    }

    const create = document.createElement("button");

    create.textContent = "Create Trust Room";
    create.className = "create-room";
    create.addEventListener("click", createRoom);

    userList.appendChild(create);
}

async function createRoom() {
    if (currentRoom) {
        return;
    }

    try {
        const data = await request("/room/create", {
            method: "POST",
            body: JSON.stringify({
                username
            })
        });

        currentRoom = data.room;
        roomPartner = "";

        openRoom("Waiting for someone to join...");
    } catch (error) {
        console.error(error);

        if (error.message === "already_in_room") {
            alert("You are already in a Trust Room.");
        } else {
            alert("Could not create Trust Room.");
        }
    }
}

async function joinRoom(room) {
    if (currentRoom) {
        return;
    }

    try {
        const data = await request("/room/join", {
            method: "POST",
            body: JSON.stringify({
                username,
                room
            })
        });

        currentRoom = room;
        roomPartner = data.host;

        openRoom(data.host);

        addMessage("system", "You joined the Trust Room.");
    } catch (error) {
        console.error(error);

        if (error.message === "already_in_room") {
            alert("You are already in a Trust Room.");
        } else {
            alert("That room is no longer available.");
        }
    }
}

function openRoom(partner) {
    users.hidden = true;
    chat.hidden = false;

    chatUser.textContent = partner;
    messages.innerHTML = "";

    renderedRoomMessages = 0;
    secureConnectionMessageShown = false;
    roomClosingMessageShown = false;
    secureConnected = false;

    closePeer();

    secureButton.disabled = false;
    secureButton.textContent = "Start Secure Chat";

    messageInput.disabled = false;
    sendButton.disabled = false;

    delete messages.dataset.partnerAccepted;
    delete messages.dataset.userAccepted;
    delete messages.dataset.connectionStarting;

    if (!partner || partner === "Waiting for someone to join...") {
        addMessage("system", "Trust Room created.");
        addMessage("system", "Waiting for someone to join...");
    }

    clearTimeout(roomPoll);
    roomPoll = null;

    clearTimeout(signalPoll);
    signalPoll = null;

    stopPollingCountdown();
    startSignalPolling();
    startPollingCountdown();
}

async function pollRoom() {
    if (!currentRoom || secureConnected) {
        stopPollingCountdown();
        return;
    }

    try {
        const data = await request(
            `/room?room=${encodeURIComponent(currentRoom)}`
        );

        if (
            data.delete_at &&
            data.guest === null &&
            !roomClosingMessageShown
        ) {
            roomClosingMessageShown = true;

            addMessage(
                "system",
                "The other user has left the room. This room will be deleted in 5 seconds."
            );

            messageInput.disabled = true;
            sendButton.disabled = true;
            secureButton.disabled = true;
        }

        if (data.guest && username === data.host) {
            if (roomPartner !== data.guest) {
                roomPartner = data.guest;
                chatUser.textContent = roomPartner;

                addMessage(
                    "system",
                    `${roomPartner} joined the Trust Room.`
                );
            }
        }

        if (data.host && username === data.guest) {
            if (roomPartner !== data.host) {
                roomPartner = data.host;
                chatUser.textContent = roomPartner;
            }
        }

        renderRoomMessages(data.messages || []);

        const secure = data.secure || {};

        if (
            roomPartner &&
            secure[roomPartner] === true &&
            !messages.dataset.partnerAccepted
        ) {
            messages.dataset.partnerAccepted = "true";

            addMessage(
                "system",
                `${roomPartner} agreed to establish a secure session.`
            );
        }

        if (
            secure[username] === true &&
            !messages.dataset.userAccepted
        ) {
            messages.dataset.userAccepted = "true";
        }

        if (
            data.host &&
            data.guest &&
            !data.delete_at &&
            secure[data.host] === true &&
            secure[data.guest] === true &&
            !peer &&
            !messages.dataset.connectionStarting
        ) {
            messages.dataset.connectionStarting = "true";

            addMessage(
                "system",
                "Both users agreed. Establishing P2P connection..."
            );

            await startSecureConnection(username === data.host);
        }
    } catch (error) {
        console.error(error);
    }

    if (currentRoom && !secureConnected) {
        startPollingCountdown();
    } else {
        stopPollingCountdown();
    }
}

function renderRoomMessages(roomMessages) {
    if (roomMessages.length <= renderedRoomMessages) {
        return;
    }

    for (const message of roomMessages.slice(renderedRoomMessages)) {
        addRoomMessage(message.username, message.message);
    }

    renderedRoomMessages = roomMessages.length;
}

function addRoomMessage(sender, text) {
    const element = document.createElement("div");
    element.className = "message room-message";

    const strong = document.createElement("strong");
    strong.textContent = `${sender}: `;

    const content = document.createElement("span");
    content.textContent = text;

    element.appendChild(strong);
    element.appendChild(content);

    messages.appendChild(element);
    messages.scrollTop = messages.scrollHeight;
}

async function sendRoomMessage() {
    const text = messageInput.value.trim();

    if (!text || !currentRoom || !roomPartner) {
        return;
    }

    try {
        if (
            secureConnected &&
            channel &&
            channel.readyState === "open"
        ) {
            channel.send(
                JSON.stringify({
                    type: "text",
                    username,
                    message: text
                })
            );

            addMessage(username, text);
        } else {
            await request("/room/message", {
                method: "POST",
                body: JSON.stringify({
                    room: currentRoom,
                    username,
                    message: text
                })
            });
        }

        messageInput.value = "";
    } catch (error) {
        console.error(error);
    }
}

async function acceptSecureChat() {
    if (
        !currentRoom ||
        !roomPartner ||
        messages.dataset.userAccepted ||
        secureButton.disabled
    ) {
        return;
    }

    secureButton.disabled = true;
    secureButton.textContent = "Waiting...";

    try {
        await request("/room/secure", {
            method: "POST",
            body: JSON.stringify({
                room: currentRoom,
                username,
                accept: true
            })
        });

        messages.dataset.userAccepted = "true";

        addMessage(
            "system",
            "You agreed to establish a secure session."
        );
    } catch (error) {
        console.error(error);

        secureButton.disabled = false;
        secureButton.textContent = "Start Secure Chat";

        alert("Could not establish secure agreement.");
    }
}

async function startSecureConnection(initiator) {
    if (peer) {
        return;
    }

    pendingIceCandidates = [];
    peer = createPeer();

    if (!initiator) {
        return;
    }

    channel = peer.createDataChannel("chat");
    setupChannel(channel);

    const offer = await peer.createOffer();

    await peer.setLocalDescription(offer);

    await sendSignal({
        type: "offer",
        target: roomPartner,
        offer: peer.localDescription
    });
}

function createPeer() {
    const connection = new RTCPeerConnection(rtcConfig);

    connection.addEventListener("icecandidate", event => {
        if (!event.candidate || !roomPartner) {
            return;
        }

        sendSignal({
            type: "ice",
            target: roomPartner,
            candidate: event.candidate
        }).catch(console.error);
    });

    connection.addEventListener("datachannel", event => {
        channel = event.channel;
        setupChannel(channel);
    });

    connection.addEventListener("connectionstatechange", () => {
        if (
            connection.connectionState === "connected" &&
            !secureConnectionMessageShown
        ) {
            secureConnectionMessageShown = true;
            secureConnected = true;

            clearTimeout(signalPoll);
            signalPoll = null;

            stopPollingCountdown();

            secureButton.textContent = "Established";
            secureButton.disabled = true;

            addMessage(
                "system",
                "Secure P2P connection established."
            );
        }

        if (
            connection.connectionState === "disconnected" ||
            connection.connectionState === "failed" ||
            connection.connectionState === "closed"
        ) {
            secureConnected = false;
        }

        if (connection.connectionState === "failed") {
            secureButton.textContent = "Connection Failed";
            secureButton.disabled = false;

            addMessage(
                "system",
                "P2P connection failed."
            );

            if (currentRoom) {
                startPollingCountdown();
            }
        }
    });

    return connection;
}

function setupChannel(dataChannel) {
    dataChannel.addEventListener("message", event => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === "text") {
                addMessage(data.username, data.message);
            }
        } catch (error) {
            console.error(error);
        }
    });
}

async function sendSignal(data) {
    await request("/signal", {
        method: "POST",
        body: JSON.stringify({
            ...data,
            from: username
        })
    });
}

function startSignalPolling() {
    clearTimeout(signalPoll);
    signalPoll = null;

    if (!currentRoom || secureConnected) {
        return;
    }

    pollSignals();
}

async function pollSignals() {
    if (!currentRoom || secureConnected) {
        signalPoll = null;
        return;
    }

    try {
        const data = await request(
            `/signals?username=${encodeURIComponent(username)}`
        );

        for (const signal of data.signals || []) {
            if (signal.type === "offer") {
                await handleOffer(signal);
            } else if (signal.type === "answer") {
                await handleAnswer(signal);
            } else if (signal.type === "ice") {
                await handleIce(signal);
            }
        }
    } catch (error) {
        console.error(error);
    }

    if (currentRoom && !secureConnected) {
        signalPoll = setTimeout(pollSignals, SIGNAL_POLL_INTERVAL);
    } else {
        signalPoll = null;
    }
}

async function handleOffer(signal) {
    if (peer) {
        return;
    }

    roomPartner = signal.from;
    chatUser.textContent = roomPartner;

    peer = createPeer();

    await peer.setRemoteDescription(signal.offer);

    const answer = await peer.createAnswer();

    await peer.setLocalDescription(answer);

    await sendSignal({
        type: "answer",
        target: roomPartner,
        answer: peer.localDescription
    });

    await flushIceCandidates();
}

async function handleAnswer(signal) {
    if (!peer) {
        return;
    }

    await peer.setRemoteDescription(signal.answer);
    await flushIceCandidates();
}

async function handleIce(signal) {
    if (!peer) {
        return;
    }

    if (!peer.remoteDescription) {
        pendingIceCandidates.push(signal.candidate);
        return;
    }

    try {
        await peer.addIceCandidate(signal.candidate);
    } catch (error) {
        console.error(error);
    }
}

async function flushIceCandidates() {
    if (!peer || !peer.remoteDescription) {
        return;
    }

    const candidates = pendingIceCandidates;
    pendingIceCandidates = [];

    for (const candidate of candidates) {
        try {
            await peer.addIceCandidate(candidate);
        } catch (error) {
            console.error(error);
        }
    }
}

function addMessage(sender, text) {
    const element = document.createElement("div");
    element.className = "message";

    const strong = document.createElement("strong");
    strong.textContent = `${sender}: `;

    const content = document.createElement("span");
    content.textContent = text;

    element.appendChild(strong);
    element.appendChild(content);

    messages.appendChild(element);
    messages.scrollTop = messages.scrollHeight;
}

async function leaveRoom() {
    if (!currentRoom) {
        return;
    }

    const room = currentRoom;

    currentRoom = "";

    clearTimeout(roomPoll);
    roomPoll = null;

    clearTimeout(signalPoll);
    signalPoll = null;

    stopPollingCountdown();

    try {
        await request("/room/leave", {
            method: "POST",
            body: JSON.stringify({
                room,
                username
            })
        });
    } catch (error) {
        console.error(error);
    }

    closePeer();

    roomPartner = "";
    renderedRoomMessages = 0;
    secureConnectionMessageShown = false;
    roomClosingMessageShown = false;
    secureConnected = false;

    delete messages.dataset.partnerAccepted;
    delete messages.dataset.userAccepted;
    delete messages.dataset.connectionStarting;

    secureButton.disabled = false;
    secureButton.textContent = "Start Secure Chat";

    messageInput.disabled = false;
    sendButton.disabled = false;

    chat.hidden = true;
    users.hidden = false;

    await updateLobby();
}

function leaveLocalRoom() {
    currentRoom = "";

    clearTimeout(roomPoll);
    roomPoll = null;

    clearTimeout(signalPoll);
    signalPoll = null;

    stopPollingCountdown();

    closePeer();

    roomPartner = "";
    renderedRoomMessages = 0;
    secureConnectionMessageShown = false;
    roomClosingMessageShown = false;
    secureConnected = false;

    delete messages.dataset.partnerAccepted;
    delete messages.dataset.userAccepted;
    delete messages.dataset.connectionStarting;

    secureButton.disabled = false;
    secureButton.textContent = "Start Secure Chat";

    messageInput.disabled = false;
    sendButton.disabled = false;

    chat.hidden = true;
    users.hidden = false;

    updateLobby();
}

function closePeer() {
    pendingIceCandidates = [];
    secureConnected = false;

    if (channel) {
        channel.close();
    }

    if (peer) {
        peer.close();
    }

    channel = null;
    peer = null;
}

showIdentityNotice();
setPollingStatus("Polling: Off");
