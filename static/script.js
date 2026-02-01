// --- 1. CONFIGURATION & SOCKET INIT ---
const socket = io({ 
    transports: ['websocket', 'polling'],
    reconnectionAttempts: 5,
    auth: {
        username: typeof CURRENT_USERNAME !== 'undefined' ? CURRENT_USERNAME : 'Guest',
        userId: typeof USER_ID !== 'undefined' ? USER_ID : null
    }
});

// User information
const USERNAME = typeof CURRENT_USERNAME !== 'undefined' ? CURRENT_USERNAME : 'Guest';
const IS_ADMIN = typeof IS_ADMIN !== 'undefined' ? IS_ADMIN : false;
const USER_ID = typeof USER_ID !== 'undefined' ? USER_ID : null;

// State management
let markers = new Map(); // Use Map instead of object for better performance
let map = null;
let userLocationWatchId = null;

// Agora RTC Configuration
const APP_ID = "YOUR_AGORA_APP_ID"; // Replace with your actual AppID
const CHANNEL = "main_room";
const TOKEN_URL = "/generate-agora-token"; // Your backend endpoint for token generation
const agoraClient = AgoraRTC.createClient({ mode: "rtc", codec: "vp8" });
let localTracks = {
    videoTrack: null,
    audioTrack: null
};
let isJoined = false;
let remoteUsers = new Map(); // Track remote users

// --- 2. HELPER FUNCTIONS ---
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${message}</span>
            <button class="notification-close">&times;</button>
        </div>
    `;
    
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${type === 'error' ? '#f44336' : type === 'success' ? '#4caf50' : '#2196f3'};
        color: white;
        padding: 12px 24px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
    `;
    
    document.body.appendChild(notification);
    
    // Close button
    notification.querySelector('.notification-close').addEventListener('click', () => {
        notification.remove();
    });
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// --- 3. ADMIN & MEDIA SYNC ---
function broadcastMedia() {
    if (!IS_ADMIN) {
        showNotification('Only administrators can broadcast media', 'error');
        return;
    }
    
    const input = document.getElementById('video-url-input');
    const url = input.value.trim();
    
    if (!url) {
        showNotification('Please enter a video URL', 'error');
        return;
    }
    
    // Validate URL
    try {
        new URL(url);
    } catch (e) {
        showNotification('Please enter a valid URL', 'error');
        return;
    }
    
    socket.emit('admin_push_media', { 
        url: url,
        admin: USERNAME,
        timestamp: Date.now()
    });
    
    showNotification('Broadcasting media to all users...', 'success');
    input.value = '';
}

socket.on('sync_media', (data) => {
    const viewport = document.getElementById('media-viewport');
    const label = document.getElementById('player-label');
    const overlay = document.getElementById('player-overlay');
    
    if (!viewport) return;
    
    const url = data.url.toLowerCase();
    const videoId = extractYouTubeId(data.url);
    
    // Hide overlay
    if (overlay) overlay.style.display = 'none';
    
    // Clear previous content
    viewport.innerHTML = '';
    
    if (videoId) {
        // YouTube embed
        const iframe = document.createElement('iframe');
        iframe.width = '100%';
        iframe.height = '100%';
        iframe.src = `https://www.youtube.com/embed/${videoId}?autoplay=1&mute=0&enablejsapi=1`;
        iframe.frameBorder = '0';
        iframe.allow = 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture';
        iframe.allowFullscreen = true;
        viewport.appendChild(iframe);
        label.textContent = "📺 Live Stream / YouTube";
    } 
    else if (url.match(/\.(mp4|webm|ogg|mov|avi|mkv)$/)) {
        // Direct video file
        const video = document.createElement('video');
        video.id = 'sync-video';
        video.controls = true;
        video.autoplay = true;
        video.style.cssText = 'width:100%; height:100%; object-fit: contain;';
        
        // Add error handling
        video.onerror = () => {
            showNotification('Failed to load video. Please check the URL.', 'error');
            if (overlay) overlay.style.display = 'flex';
        };
        
        const source = document.createElement('source');
        source.src = data.url;
        source.type = getVideoType(data.url);
        
        video.appendChild(source);
        viewport.appendChild(video);
        label.textContent = "🎬 Movie Night";
    }
    else if (url.includes('twitch.tv')) {
        // Twitch embed
        const channel = url.split('/').pop();
        const iframe = document.createElement('iframe');
        iframe.width = '100%';
        iframe.height = '100%';
        iframe.src = `https://player.twitch.tv/?channel=${channel}&parent=${window.location.hostname}`;
        iframe.frameBorder = '0';
        iframe.allowFullscreen = true;
        viewport.appendChild(iframe);
        label.textContent = "🎮 Twitch Stream";
    }
    else {
        showNotification('Unsupported media format', 'error');
        if (overlay) overlay.style.display = 'flex';
    }
});

function extractYouTubeId(url) {
    const patterns = [
        /(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/,
        /youtube\.com\/embed\/([a-zA-Z0-9_-]{11})/,
        /youtube\.com\/v\/([a-zA-Z0-9_-]{11})/
    ];
    
    for (const pattern of patterns) {
        const match = url.match(pattern);
        if (match && match[1]) {
            return match[1];
        }
    }
    return null;
}

function getVideoType(url) {
    const extension = url.split('.').pop().toLowerCase();
    const types = {
        'mp4': 'video/mp4',
        'webm': 'video/webm',
        'ogg': 'video/ogg',
        'mov': 'video/quicktime',
        'avi': 'video/x-msvideo',
        'mkv': 'video/x-matroska'
    };
    return types[extension] || 'video/mp4';
}

// --- 4. AGORA VIDEO CALL LOGIC ---
async function getAgoraToken(channel) {
    try {
        const response = await fetch(`${TOKEN_URL}?channel=${channel}&uid=${USER_ID || USERNAME}`);
        if (!response.ok) throw new Error('Token generation failed');
        const data = await response.json();
        return data.token;
    } catch (error) {
        console.error('Failed to get Agora token:', error);
        return null;
    }
}

async function toggleLivestream() {
    const btn = document.getElementById('btn-join');
    const leaveBtn = document.getElementById('btn-leave');
    const videoGrid = document.getElementById('video-grid');
    
    if (!isJoined) {
        // JOIN VIDEO CALL
        try {
            // Get dynamic token from server
            const token = await getAgoraToken(CHANNEL);
            if (!token) {
                showNotification('Failed to get authentication token', 'error');
                return;
            }
            
            // Clear video grid except for placeholders
            videoGrid.innerHTML = '<div class="video-container" id="local-video-container"></div>';
            
            // Join channel
            await agoraClient.join(APP_ID, CHANNEL, token, USER_ID || USERNAME);
            
            // Create local tracks
            localTracks.audioTrack = await AgoraRTC.createMicrophoneAudioTrack();
            localTracks.videoTrack = await AgoraRTC.createCameraVideoTrack();
            
            // Create local video container
            const localContainer = document.getElementById('local-video-container');
            localContainer.innerHTML = `
                <div class="video-header">
                    <span class="video-username">${USERNAME} (You)</span>
                    <div class="video-controls">
                        <button class="control-btn mic-toggle" onclick="toggleMicrophone()">🎤</button>
                        <button class="control-btn camera-toggle" onclick="toggleCamera()">📷</button>
                    </div>
                </div>
            `;
            
            // Play local video
            localTracks.videoTrack.play(localContainer);
            
            // Publish tracks
            await agoraClient.publish([localTracks.audioTrack, localTracks.videoTrack]);
            
            // Update UI
            isJoined = true;
            btn.style.display = 'none';
            if (leaveBtn) leaveBtn.style.display = 'inline-block';
            
            showNotification('Joined video call successfully', 'success');
            
        } catch (error) {
            console.error('Failed to join video call:', error);
            showNotification(`Failed to join: ${error.message}`, 'error');
            
            // Clean up on error
            for (let trackName in localTracks) {
                if (localTracks[trackName]) {
                    localTracks[trackName].stop();
                    localTracks[trackName].close();
                    localTracks[trackName] = null;
                }
            }
        }
    } else {
        // LEAVE VIDEO CALL
        await leaveVideoCall();
    }
}

async function leaveVideoCall() {
    try {
        // Unpublish and close local tracks
        if (localTracks.audioTrack) {
            localTracks.audioTrack.stop();
            localTracks.audioTrack.close();
            localTracks.audioTrack = null;
        }
        if (localTracks.videoTrack) {
            localTracks.videoTrack.stop();
            localTracks.videoTrack.close();
            localTracks.videoTrack = null;
        }
        
        // Leave channel
        await agoraClient.leave();
        
        // Clear video grid
        const videoGrid = document.getElementById('video-grid');
        videoGrid.innerHTML = `
            <div class="video-container">
                <div class="overlay">
                    <p>No one is in the call yet</p>
                    <p style="font-size: 0.8rem; margin-top: 10px; opacity: 0.8;">
                        Click "Join Video Call" to start
                    </p>
                </div>
            </div>
        `;
        
        // Update UI
        isJoined = false;
        document.getElementById('btn-join').style.display = 'inline-block';
        document.getElementById('btn-leave').style.display = 'none';
        
        showNotification('Left video call', 'info');
        
    } catch (error) {
        console.error('Error leaving call:', error);
    }
}

async function toggleMicrophone() {
    if (localTracks.audioTrack) {
        const enabled = !localTracks.audioTrack.enabled;
        await localTracks.audioTrack.setEnabled(enabled);
        document.querySelector('.mic-toggle').textContent = enabled ? '🎤' : '🔇';
        showNotification(enabled ? 'Microphone on' : 'Microphone muted', 'info');
    }
}

async function toggleCamera() {
    if (localTracks.videoTrack) {
        const enabled = !localTracks.videoTrack.enabled;
        await localTracks.videoTrack.setEnabled(enabled);
        document.querySelector('.camera-toggle').textContent = enabled ? '📷' : '📹';
        showNotification(enabled ? 'Camera on' : 'Camera off', 'info');
    }
}

// Handle remote users
agoraClient.on("user-published", async (user, mediaType) => {
    await agoraClient.subscribe(user, mediaType);
    
    if (mediaType === "video") {
        // Create container for remote user
        const remoteContainer = document.createElement('div');
        remoteContainer.className = 'video-container';
        remoteContainer.id = `remote-${user.uid}`;
        remoteContainer.innerHTML = `
            <div class="video-header">
                <span class="video-username">${user.uid}</span>
            </div>
        `;
        
        document.getElementById('video-grid').appendChild(remoteContainer);
        user.videoTrack.play(remoteContainer);
        remoteUsers.set(user.uid, { element: remoteContainer, track: user.videoTrack });
    }
    
    if (mediaType === "audio") {
        user.audioTrack.play();
    }
});

agoraClient.on("user-unpublished", (user, mediaType) => {
    if (mediaType === "video") {
        const remoteUser = remoteUsers.get(user.uid);
        if (remoteUser) {
            remoteUser.element.remove();
            remoteUsers.delete(user.uid);
        }
    }
});

agoraClient.on("user-left", (user) => {
    const remoteUser = remoteUsers.get(user.uid);
    if (remoteUser) {
        remoteUser.element.remove();
        remoteUsers.delete(user.uid);
    }
});

// --- 5. MAP & GEOLOCATION ---
function initMap() {
    const mapTarget = document.getElementById('map');
    if (!mapTarget) return;
    
    map = L.map(mapTarget).setView([20, 0], 2);
    
    L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
        attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors, © <a href="https://carto.com/attributions">CARTO</a>',
        maxZoom: 19,
        minZoom: 1
    }).addTo(map);
    
    // Add scale control
    L.control.scale().addTo(map);
    
    // Load initial markers
    updateMarkers();
}

async function updateMarkers() {
    try {
        const response = await fetch('/api/members/locations');
        if (!response.ok) throw new Error('Failed to fetch locations');
        
        const members = await response.json();
        
        members.forEach(member => {
            if (!member.lat || !member.lng) return;
            
            const key = member.id || member.username;
            
            if (markers.has(key)) {
                // Update existing marker
                const marker = markers.get(key);
                marker.setLatLng([member.lat, member.lng]);
                
                // Update popup if points changed
                const popup = marker.getPopup();
                if (popup && popup.isOpen()) {
                    marker.setPopupContent(createPopupContent(member));
                }
            } else {
                // Create new marker
                const marker = L.marker([member.lat, member.lng], {
                    icon: createCustomIcon(member)
                }).addTo(map);
                
                marker.bindPopup(createPopupContent(member));
                markers.set(key, marker);
            }
        });
        
        // Remove markers for users no longer online
        const currentKeys = members.map(m => m.id || m.username);
        for (const [key, marker] of markers.entries()) {
            if (!currentKeys.includes(key)) {
                map.removeLayer(marker);
                markers.delete(key);
            }
        }
        
    } catch (error) {
        console.error('Map update error:', error);
        showNotification('Failed to update map locations', 'error');
    }
}

function createCustomIcon(member) {
    return L.divIcon({
        className: 'custom-marker',
        html: `
            <div class="marker-icon" style="
                background: ${member.active ? '#22c55e' : '#94a3b8'};
                width: 32px;
                height: 32px;
                border-radius: 50%;
                border: 3px solid white;
                box-shadow: 0 2px 6px rgba(0,0,0,0.3);
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 12px;
            ">
                ${member.username.charAt(0).toUpperCase()}
            </div>
        `,
        iconSize: [32, 32],
        iconAnchor: [16, 32]
    });
}

function createPopupContent(member) {
    return `
        <div class="map-popup">
            <strong>${member.username}</strong>
            ${member.points ? `<br>🏆 Points: ${member.points}` : ''}
            ${member.status ? `<br>📱 Status: ${member.status}` : ''}
            ${member.lastSeen ? `<br>⏰ Last active: ${new Date(member.lastSeen).toLocaleTimeString()}` : ''}
        </div>
    `;
}

function locateMe() {
    if (!navigator.geolocation) {
        showNotification('Geolocation is not supported by your browser', 'error');
        return;
    }
    
    // Stop any existing watcher
    if (userLocationWatchId) {
        navigator.geolocation.clearWatch(userLocationWatchId);
    }
    
    navigator.geolocation.getCurrentPosition(
        (position) => {
            const { latitude, longitude } = position.coords;
            
            // Emit location to server
            socket.emit('update_location', {
                lat: latitude,
                lng: longitude,
                username: USERNAME,
                timestamp: Date.now()
            });
            
            // Center map on user
            if (map) {
                map.setView([latitude, longitude], 13);
                
                // Add user marker if not already present
                if (!markers.has(USERNAME)) {
                    const marker = L.marker([latitude, longitude], {
                        icon: createCustomIcon({ username: USERNAME, active: true })
                    }).addTo(map);
                    marker.bindPopup(`<strong>${USERNAME} (You)</strong>`);
                    markers.set(USERNAME, marker);
                }
            }
            
            showNotification('Location shared successfully', 'success');
        },
        (error) => {
            let message = 'Unable to retrieve your location';
            switch(error.code) {
                case error.PERMISSION_DENIED:
                    message = 'Location permission denied. Please enable location services.';
                    break;
                case error.POSITION_UNAVAILABLE:
                    message = 'Location information is unavailable.';
                    break;
                case error.TIMEOUT:
                    message = 'Location request timed out.';
                    break;
            }
            showNotification(message, 'error');
        },
        {
            enableHighAccuracy: true,
            timeout: 10000,
            maximumAge: 0
        }
    );
}

// --- 6. CHAT FUNCTIONALITY ---
function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    
    if (!message) return;
    
    // Check for private message
    if (message.startsWith('/w ')) {
        const parts = message.split(' ');
        if (parts.length >= 3) {
            const recipient = parts[1];
            const privateMsg = parts.slice(2).join(' ');
            socket.emit('private_message', {
                to: recipient,
                message: privateMsg,
                from: USERNAME
            });
            addMessageToChat(`${USERNAME} → ${recipient}: ${privateMsg}`, true);
        }
    } else {
        socket.emit('chat_message', {
            username: USERNAME,
            message: message,
            timestamp: Date.now()
        });
        addMessageToChat(`${USERNAME}: ${message}`, true);
    }
    
    input.value = '';
    input.focus();
}

function addMessageToChat(message, isOwn = false) {
    const messagesDiv = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isOwn ? 'own' : 'others'}`;
    messageDiv.innerHTML = `
        <div class="message-sender">${isOwn ? 'You' : message.split(':')[0]}</div>
        <div class="message-content">${message.split(':').slice(1).join(':').trim() || message}</div>
    `;
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Socket event listeners for chat
socket.on('chat_message', (data) => {
    if (data.username !== USERNAME) {
        addMessageToChat(`${data.username}: ${data.message}`, false);
    }
});

socket.on('private_message', (data) => {
    if (data.to === USERNAME || data.from === USERNAME) {
        const sender = data.from === USERNAME ? 'You' : data.from;
        const recipient = data.to === USERNAME ? 'you' : data.to;
        addMessageToChat(`${sender} → ${recipient}: ${data.message}`, data.from === USERNAME);
    }
});

socket.on('user_connected', (data) => {
    showNotification(`${data.username} connected`, 'info');
    updateOnlineCount(data.onlineCount);
});

socket.on('user_disconnected', (data) => {
    showNotification(`${data.username} disconnected`, 'info');
    updateOnlineCount(data.onlineCount);
});

function updateOnlineCount(count) {
    const badge = document.getElementById('online-count');
    if (badge) badge.textContent = `${count} online`;
}

// --- 7. INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    // Initialize map
    initMap();
    
    // Set up event listeners
    document.getElementById('btn-join')?.addEventListener('click', toggleLivestream);
    document.getElementById('btn-leave')?.addEventListener('click', leaveVideoCall);
    
    const chatInput = document.getElementById('chat-input');
    if (chatInput) {
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });
    }
    
    // Add geolocation button if exists
    const locateBtn = document.querySelector('[onclick="locateMe()"]');
    if (locateBtn) {
        locateBtn.addEventListener('click', locateMe);
    }
    
    // Start periodic updates
    setInterval(updateMarkers, 30000); // Update every 30 seconds
    
    // Handle window unload
    window.addEventListener('beforeunload', () => {
        if (isJoined) {
            leaveVideoCall();
        }
        if (userLocationWatchId) {
            navigator.geolocation.clearWatch(userLocationWatchId);
        }
        socket.emit('user_leaving', { username: USERNAME });
    });
});

// Error handling
socket.on('connect_error', (error) => {
    console.error('Socket connection error:', error);
    showNotification('Connection lost. Attempting to reconnect...', 'error');
});

socket.on('connect', () => {
    console.log('Socket connected');
    showNotification('Connected to server', 'success');
    
    // Join user to socket room
    socket.emit('user_joined', {
        username: USERNAME,
        userId: USER_ID,
        isAdmin: IS_ADMIN
    });
});

socket.on('disconnect', () => {
    showNotification('Disconnected from server', 'error');
});