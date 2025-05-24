// server.js - Updated for User Authentication
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // For password hashing
const jwt = require('jsonwebtoken'); // For creating JSON Web Tokens
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// --- Configuration (for JWT) ---
// IMPORTANT: In a real app, store this securely in environment variables!
const JWT_SECRET = '454f3a456f6554297b5e8c0516e2eb340ca41dfdf0cd1f56061369e72f4291f4fb5b4643b211e60db22bf6de246cea035999d78f4c7771c8ca28923b01ed1531'; // Replace with a strong, random secret key!
// You can generate a random string: require('crypto').randomBytes(64).toString('hex') in node console

// --- Temporary "Database" (in-memory arrays for appointments and users) ---
// IMPORTANT: This data will reset every time the server restarts.
// For a real app, you would connect to a persistent database (MongoDB, PostgreSQL etc.)
let appointments = [];
let users = []; // New array to store user data (id, username, hashedPassword)

// Example initial appointments (will still reset on server restart)
appointments.push({ id: 'app1', time: '09:00', userName: 'Alice', status: 'pending', bookedAt: new Date().toLocaleString() });
appointments.push({ id: 'app2', time: '10:00', userName: 'Bob', status: 'accepted', bookedAt: new Date().toLocaleString() });
appointments.push({ id: 'app3', time: '14:00', userName: 'Charlie', status: 'pending', bookedAt: new Date().toLocaleString() });

// --- Helper function for generating unique IDs ---
function generateId() {
    return '_' + Math.random().toString(36).substr(2, 9);
}

// --- Middleware for authenticating JWT tokens ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token
        req.user = user; // user payload from JWT (e.g., { id: 'user123', username: 'testuser' })
        next();
    });
};

// --- Authentication Endpoints ---

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Check if user already exists
    if (users.some(user => user.username === username)) {
        return res.status(409).json({ message: 'Username already taken.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password
        const newUser = {
            id: generateId(),
            username,
            password: hashedPassword,
            role: 'service_taker' // Default role
        };
        users.push(newUser);
        console.log('New user registered:', username);
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// POST /api/login - Log in a user
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials.' });
    }

    try {
        if (await bcrypt.compare(password, user.password)) {
            // Create a JWT token
            const accessToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
            console.log('User logged in:', username);
            res.json({ message: 'Logged in successfully!', accessToken, username: user.username, userId: user.id });
        } else {
            res.status(400).json({ message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- API Endpoints (Routes) ---

// GET /api/appointments - Get all appointments (Accessible to all for now)
app.get('/api/appointments', (req, res) => {
    console.log('GET /api/appointments requested');
    res.json(appointments);
});

// POST /api/appointments - Create a new appointment (Requires authentication)
app.post('/api/appointments', authenticateToken, (req, res) => { // Added authenticateToken middleware
    const { time } = req.body; // No need for userName from body, take from authenticated user
    const { id: userId, username } = req.user; // Get user info from authenticated token

    if (!time) {
        return res.status(400).json({ message: 'Time is required.' });
    }

    // Check if the slot is already booked
    const isSlotBooked = appointments.some(app => app.time === time && (app.status === 'pending' || app.status === 'accepted'));
    if (isSlotBooked) {
        return res.status(409).json({ message: 'This time slot is already booked.' });
    }

    const newAppointment = {
        id: generateId(),
        time,
        userName: username, // Use authenticated username
        userId: userId,     // Store the user ID for ownership
        status: 'pending',
        bookedAt: new Date().toLocaleString()
    };
    appointments.push(newAppointment);
    console.log(`New appointment created for ${username}:`, newAppointment);
    res.status(201).json(newAppointment);
});

// GET /api/my-appointments - Get appointments for the logged-in user (Requires authentication)
app.get('/api/my-appointments', authenticateToken, (req, res) => {
    const userAppointments = appointments.filter(app => app.userId === req.user.id);
    res.json(userAppointments);
});


// PUT /api/appointments/:id - Update an appointment (Requires authentication and proper role/ownership)
app.put('/api/appointments/:id', authenticateToken, (req, res) => { // Added authenticateToken
    const { id } = req.params;
    const { status } = req.body;
    const appointmentIndex = appointments.findIndex(app => app.id === id);

    if (appointmentIndex === -1) {
        return res.status(404).json({ message: 'Appointment not found.' });
    }

    const appointment = appointments[appointmentIndex];

    // Basic authorization: Only the owner or a service provider can change status/update
    // For now, let's allow service_provider role to update any, and owners to cancel their own.
    if (req.user.role === 'service_taker' && appointment.userId !== req.user.id) {
        return res.status(403).json({ message: 'Not authorized to update this appointment.' });
    }
    // More detailed logic for service provider to accept/reject
    if (req.user.role === 'service_provider' && (status === 'accepted' || status === 'rejected')) {
        // Allow service provider to change status
        appointment.status = status;
        console.log(`Appointment ${id} updated to status: ${status} by service provider.`);
        return res.json(appointment);
    } else if (req.user.role === 'service_taker' && status === 'cancelled' && appointment.userId === req.user.id) {
        // Allow service taker to cancel their own appointment
        appointment.status = 'cancelled';
        console.log(`Appointment ${id} cancelled by user ${req.user.username}.`);
        return res.json(appointment);
    } else {
        // Prevent other types of updates or unauthorized updates
        return res.status(403).json({ message: 'Unauthorized update attempt or invalid status.' });
    }
});

// DELETE /api/appointments/:id - Delete an appointment (Requires authentication and proper role/ownership)
app.delete('/api/appointments/:id', authenticateToken, (req, res) => { // Added authenticateToken
    const { id } = req.params;
    const appointmentIndex = appointments.findIndex(app => app.id === id);

    if (appointmentIndex === -1) {
        return res.status(404).json({ message: 'Appointment not found.' });
    }

    const appointment = appointments[appointmentIndex];

    // Authorization: Only the owner can delete their own, or a service_provider can delete any.
    if (req.user.role === 'service_taker' && appointment.userId !== req.user.id) {
        return res.status(403).json({ message: 'Not authorized to delete this appointment.' });
    }

    appointments.splice(appointmentIndex, 1); // Remove the appointment
    console.log(`Appointment ${id} deleted.`);
    res.status(204).send();
});


// Simple root route for testing if server is running
app.get('/', (req, res) => {
    res.send('Slotly Backend API is running!');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Slotly Backend API listening at http://localhost:${PORT}`);
    console.log('Initial appointments:', appointments);
    console.log('Initial users:', users); // Show initial users (empty by default)
});