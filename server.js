const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');

// Load environment variables
require('dotenv').config();

// Configure multer for profile picture uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        // Check if file is an image
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// User authentication storage
const USERS_FILE = path.join(__dirname, 'users.json');
let registeredUsers = new Map(); // username -> { password, userId, email }

// Load users from file on startup
function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            const usersArray = JSON.parse(data);
            registeredUsers = new Map(usersArray);
            console.log(`Loaded ${registeredUsers.size} registered users`);
        }
    } catch (error) {
        console.error('Error loading users:', error);
        registeredUsers = new Map();
    }
}

// Save users to file
function saveUsers() {
    try {
        const usersArray = Array.from(registeredUsers.entries());
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersArray, null, 2));
    } catch (error) {
        console.error('Error saving users:', error);
    }
}

// Hash password function
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Generate unique user ID
function generateUserId() {
    return crypto.randomUUID();
}

// Initialize users
loadUsers();

let PORT = process.env.PORT || 8080;

// Store connected users with their socket info
const users = new Map();
// Store user contacts and friend requests
const userContacts = new Map(); // userId -> Set of contact userIds
const friendRequests = new Map(); // userId -> Set of pending request userIds
// Store private message history
const messageHistory = new Map(); // conversationId -> Array of messages
// Store username to userId mapping
const usernameToId = new Map();
const idToUsername = new Map();

// Helper function to generate conversation ID for two users
function getConversationId(userId1, userId2) {
    return [userId1, userId2].sort().join('-');
}

// ❌ FIXED earlier duplicate import removed
// const path = require('path');

// Serve frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// Default route to always load index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});
// Serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Profile picture upload route
app.post('/upload-profile-picture', upload.single('profilePicture'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ error: 'Username required' });
        }
        
        const userData = registeredUsers.get(username.toLowerCase());
        if (!userData) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Delete old profile picture if it exists
        if (userData.profilePicture) {
            const oldPath = path.join(__dirname, userData.profilePicture);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }
        }
        
        // Update user data with new profile picture path
        const relativePath = `uploads/${req.file.filename}`;
        userData.profilePicture = relativePath;
        registeredUsers.set(username.toLowerCase(), userData);
        saveUsers();
        
        res.json({
            success: true,
            profilePicture: relativePath
        });
    } catch (error) {
        console.error('Error uploading profile picture:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // Handle user registration
    socket.on('register', (data) => {
        const { username, password, email } = data;
        
        // Validate input
        if (!username || !password) {
            socket.emit('registration failed', { message: 'Username and password are required' });
            return;
        }
        
        if (username.length < 3 || username.length > 20) {
            socket.emit('registration failed', { message: 'Username must be between 3 and 20 characters' });
            return;
        }
        
        if (password.length < 6) {
            socket.emit('registration failed', { message: 'Password must be at least 6 characters' });
            return;
        }
        
        // Check if username already exists
        if (registeredUsers.has(username.toLowerCase())) {
            socket.emit('registration failed', { message: 'Username is already taken' });
            return;
        }
        
        // Create new user
        const userId = generateUserId();
        const hashedPassword = hashPassword(password);
        
        registeredUsers.set(username.toLowerCase(), {
            password: hashedPassword,
            userId: userId,
            email: email || '',
            originalUsername: username,
            createdAt: new Date().toISOString(),
            profilePicture: null // Default no profile picture
        });
        
        // Save to file
        saveUsers();
        
        console.log(`New user registered: ${username}`);
        socket.emit('registration successful', { username: username });
    });
    
    // Handle user login
    socket.on('login', (data) => {
        const { username, password } = data;
        
        // Validate input
        if (!username || !password) {
            socket.emit('login failed', { message: 'Username and password are required' });
            return;
        }
        
        // Check if user exists
        const userData = registeredUsers.get(username.toLowerCase());
        if (!userData) {
            socket.emit('login failed', { message: 'Invalid username or password' });
            return;
        }
        
        // Verify password
        const hashedPassword = hashPassword(password);
        if (userData.password !== hashedPassword) {
            socket.emit('login failed', { message: 'Invalid username or password' });
            return;
        }
        
        // Check if user is already logged in
        if (usernameToId.has(userData.originalUsername)) {
            socket.emit('login failed', { message: 'User is already logged in' });
            return;
        }
        
        // Log user in
        const userId = socket.id;
        users.set(userId, {
            id: userId,
            username: userData.originalUsername,
            joinTime: new Date(),
            isOnline: true,
            persistentId: userData.userId
        });
        
        usernameToId.set(userData.originalUsername, userId);
        idToUsername.set(userId, userData.originalUsername);
        
        // Initialize or load user's contacts and friend requests based on persistent ID
        const persistentUserId = userData.userId;
        if (!userContacts.has(persistentUserId)) {
            userContacts.set(persistentUserId, new Set());
        }
        if (!friendRequests.has(persistentUserId)) {
            friendRequests.set(persistentUserId, new Set());
        }
        
        // Copy to current session ID for compatibility
        userContacts.set(userId, userContacts.get(persistentUserId));
        friendRequests.set(userId, friendRequests.get(persistentUserId));
        
        console.log(`${userData.originalUsername} logged in`);
        socket.emit('login successful', {
            userId: userId,
            username: userData.originalUsername,
            profilePicture: userData.profilePicture
        });
        
        // Send user's contacts and their online status
        const contacts = Array.from(userContacts.get(userId)).map(contactId => {
            const contactUsername = idToUsername.get(contactId);
            const isOnline = users.has(contactId);
            return {
                id: contactId,
                username: contactUsername,
                isOnline: isOnline
            };
        }).filter(contact => contact.username); // Filter out invalid contacts
        
        socket.emit('contacts list', contacts);
        
        // Send pending friend requests
        const pendingRequests = Array.from(friendRequests.get(userId)).map(requesterId => {
            return {
                id: requesterId,
                username: idToUsername.get(requesterId)
            };
        }).filter(request => request.username); // Filter out invalid requests
        
        socket.emit('friend requests', pendingRequests);
        
        // Notify contacts that this user is now online
        userContacts.get(userId).forEach(contactId => {
            if (users.has(contactId)) {
                io.to(contactId).emit('contact status changed', {
                    contactId: userId,
                    username: userData.originalUsername,
                    isOnline: true
                });
            }
        });
    });

    // ✅ NEW FEATURE: Change password
    socket.on('change password', (data) => {
        const { username, oldPassword, newPassword } = data;

        if (!username || !oldPassword || !newPassword) {
            socket.emit('password change failed', { message: 'All fields are required' });
            return;
        }

        const userData = registeredUsers.get(username.toLowerCase());
        if (!userData) {
            socket.emit('password change failed', { message: 'User not found' });
            return;
        }

        const hashedOld = hashPassword(oldPassword);
        if (userData.password !== hashedOld) {
            socket.emit('password change failed', { message: 'Incorrect old password' });
            return;
        }

        const hashedNew = hashPassword(newPassword);
        userData.password = hashedNew;
        registeredUsers.set(username.toLowerCase(), userData);
        saveUsers();

        socket.emit('password change successful', { message: 'Password updated successfully' });
        console.log(`Password changed for user: ${username}`);
    });

    // Handle friend requests
    socket.on('send friend request', (data) => {
        const { targetUsername } = data;
        const senderId = socket.id;
        const senderUsername = idToUsername.get(senderId);
        
        if (!senderUsername) {
            socket.emit('friend request failed', { message: 'You must be logged in' });
            return;
        }
        
        // Find target user
        const targetUserId = usernameToId.get(targetUsername);
        const targetUserData = registeredUsers.get(targetUsername.toLowerCase());
        
        if (!targetUserData) {
            socket.emit('friend request failed', { message: 'User not found' });
            return;
        }
        
        const targetPersistentId = targetUserData.userId;
        const senderPersistentId = registeredUsers.get(senderUsername.toLowerCase()).userId;
        
        // Check if already contacts
        if (userContacts.get(senderPersistentId)?.has(targetPersistentId)) {
            socket.emit('friend request failed', { message: 'Already in contacts' });
            return;
        }
        
        // Check if request already sent
        if (friendRequests.get(targetPersistentId)?.has(senderPersistentId)) {
            socket.emit('friend request failed', { message: 'Friend request already sent' });
            return;
        }
        
        // Add friend request
        if (!friendRequests.has(targetPersistentId)) {
            friendRequests.set(targetPersistentId, new Set());
        }
        friendRequests.get(targetPersistentId).add(senderPersistentId);
        
        // If target is online, also add to their session
        if (targetUserId) {
            if (!friendRequests.has(targetUserId)) {
                friendRequests.set(targetUserId, new Set());
            }
            friendRequests.get(targetUserId).add(senderId);
            
            // Notify target user
            io.to(targetUserId).emit('friend request received', {
                from: senderUsername,
                fromId: senderId
            });
        }
        
        socket.emit('friend request sent', { to: targetUsername });
        console.log(`Friend request sent from ${senderUsername} to ${targetUsername}`);
    });
    
    // Handle friend request responses
    socket.on('friend request response', (data) => {
        const { requesterId, accepted } = data;
        const responderId = socket.id;
        const responderUsername = idToUsername.get(responderId);
        const requesterUsername = idToUsername.get(requesterId);
        
        if (!responderUsername) {
            return;
        }
        
        const responderData = registeredUsers.get(responderUsername.toLowerCase());
        const requesterData = registeredUsers.get(requesterUsername?.toLowerCase());
        
        if (!responderData || !requesterData) {
            return;
        }
        
        const responderPersistentId = responderData.userId;
        const requesterPersistentId = requesterData.userId;
        
        // Remove friend request
        friendRequests.get(responderPersistentId)?.delete(requesterPersistentId);
        friendRequests.get(responderId)?.delete(requesterId);
        
        if (accepted) {
            // Add to contacts
            userContacts.get(responderPersistentId).add(requesterPersistentId);
            userContacts.get(requesterPersistentId).add(responderPersistentId);
            
            // Also add to session contacts
            userContacts.get(responderId).add(requesterId);
            if (userContacts.has(requesterId)) {
                userContacts.get(requesterId).add(responderId);
            }
            
            // Notify both users
            socket.emit('contact added', {
                id: requesterId,
                username: requesterUsername,
                isOnline: users.has(requesterId)
            });
            
            if (users.has(requesterId)) {
                io.to(requesterId).emit('contact added', {
                    id: responderId,
                    username: responderUsername,
                    isOnline: true
                });
            }
            
            console.log(`${responderUsername} accepted friend request from ${requesterUsername}`);
        } else {
            console.log(`${responderUsername} declined friend request from ${requesterUsername}`);
        }
        
        // Notify requester of response
        if (users.has(requesterId)) {
            io.to(requesterId).emit('friend request responded', {
                from: responderUsername,
                accepted: accepted
            });
        }
    });
    
    // Handle user search
    socket.on('search users', (data) => {
        const { query } = data;
        const searcherId = socket.id;
        const searcherUsername = idToUsername.get(searcherId);
        
        if (!searcherUsername || !query || query.trim().length < 2) {
            socket.emit('search results', []);
            return;
        }
        
        const results = [];
        const searchTerm = query.toLowerCase().trim();
        
        for (const [username, userData] of registeredUsers) {
            if (username.includes(searchTerm) && userData.originalUsername !== searcherUsername) {
                results.push({
                    username: userData.originalUsername,
                    isOnline: usernameToId.has(userData.originalUsername)
                });
            }
        }
        
        socket.emit('search results', results.slice(0, 10)); // Limit to 10 results
    });
    
    // Handle private messages
    socket.on('private message', (data) => {
        const { to, message } = data;
        const senderId = socket.id;
        const senderUsername = idToUsername.get(senderId);
        
        if (!senderUsername || !to || !message || message.trim().length === 0) {
            return;
        }
        
        const targetUserId = usernameToId.get(to);
        const senderData = registeredUsers.get(senderUsername.toLowerCase());
        const targetData = registeredUsers.get(to.toLowerCase());
        
        if (!senderData || !targetData) {
            return;
        }
        
        // Check if users are contacts
        const senderPersistentId = senderData.userId;
        const targetPersistentId = targetData.userId;
        
        if (!userContacts.get(senderPersistentId)?.has(targetPersistentId)) {
            socket.emit('message failed', { message: 'You can only message contacts' });
            return;
        }
        
        const messageData = {
            id: crypto.randomUUID(),
            from: senderUsername,
            to: to,
            message: message.trim(),
            timestamp: new Date().toISOString()
        };
        
        // Store message in history
        const conversationId = getConversationId(senderPersistentId, targetPersistentId);
        if (!messageHistory.has(conversationId)) {
            messageHistory.set(conversationId, []);
        }
        messageHistory.get(conversationId).push(messageData);
        
        // Send to both users
        socket.emit('private message', messageData);
        if (targetUserId && users.has(targetUserId)) {
            io.to(targetUserId).emit('private message', messageData);
        }
        
        console.log(`Private message from ${senderUsername} to ${to}: ${message.substring(0, 50)}...`);
    });
    
    // Handle loading message history
    socket.on('load messages', (data) => {
        const { contactUsername } = data;
        const userId = socket.id;
        const username = idToUsername.get(userId);
        
        if (!username || !contactUsername) {
            return;
        }
        
        const userData = registeredUsers.get(username.toLowerCase());
        const contactData = registeredUsers.get(contactUsername.toLowerCase());
        
        if (!userData || !contactData) {
            return;
        }
        
        const conversationId = getConversationId(userData.userId, contactData.userId);
        const messages = messageHistory.get(conversationId) || [];
        
        socket.emit('message history', {
            contactUsername: contactUsername,
            messages: messages
        });
    });
    
    // Handle typing indicators
    socket.on('typing start', (data) => {
        const { to } = data;
        const senderId = socket.id;
        const senderUsername = idToUsername.get(senderId);
        
        if (!senderUsername || !to) {
            return;
        }
        
        const targetUserId = usernameToId.get(to);
        if (targetUserId && users.has(targetUserId)) {
            io.to(targetUserId).emit('typing start', {
                from: senderUsername
            });
        }
    });
    
    socket.on('typing stop', (data) => {
        const { to } = data;
        const senderId = socket.id;
        const senderUsername = idToUsername.get(senderId);
        
        if (!senderUsername || !to) {
            return;
        }
        
        const targetUserId = usernameToId.get(to);
        if (targetUserId && users.has(targetUserId)) {
            io.to(targetUserId).emit('typing stop', {
                from: senderUsername
            });
        }
    });
    
    // Handle user disconnect
    socket.on('disconnect', () => {
        const userId = socket.id;
        const username = idToUsername.get(userId);
        
        if (username) {
            console.log(`${username} disconnected`);
            
            // Clean up user data
            users.delete(userId);
            usernameToId.delete(username);
            idToUsername.delete(userId);
            
            // Notify contacts that user is offline
            if (userContacts.has(userId)) {
                userContacts.get(userId).forEach(contactId => {
                    if (users.has(contactId)) {
                        io.to(contactId).emit('contact status changed', {
                            contactId: userId,
                            username: username,
                            isOnline: false
                        });
                    }
                });
            }
        } else {
            console.log('Unknown user disconnected:', userId);
        }
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`Chat server running on http://localhost:${PORT}`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Trying another port...`);
        PORT++;
        server.listen(PORT);
    } else {
        console.error('Server error:', err);
    }
});
