const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ============================================================
// CONFIGURATION - Edit these values for your setup
// ============================================================

const CONFIG = {
    // Server port
    port: process.env.PORT || 3000,
    
    // JWT secret for token signing
    // IMPORTANT: Keep this the same across server restarts
    // In production, set via environment variable: JWT_SECRET=your-secret-here
    jwtSecret: process.env.JWT_SECRET || 'qgi-glass-shop-secret-change-this-in-production-but-keep-it-static-4d8a9f7e2b3c1a6d5e8f9a0b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
    
    // CORS settings
    cors: {
        // Allow all origins in development, restrict in production
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'ngrok-skip-browser-warning', 'Authorization']
    },
    
    // File paths (relative to server.js location)
    files: {
        orders: path.join(__dirname, 'orders.json'),
        activity: path.join(__dirname, 'activity.json'),
        users: path.join(__dirname, 'users.json')
    }
};

// ============================================================
// End of configuration - you shouldn't need to edit below this
// ============================================================

const app = express();
const PORT = CONFIG.port;
const JWT_SECRET = CONFIG.jwtSecret;

// CORS middleware
app.use(cors(CONFIG.cors));

// body parser
app.use(express.json());

// request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// File paths (from config)
const ORDERS_FILE = CONFIG.files.orders;
const ACTIVITY_FILE = CONFIG.files.activity;
const USERS_FILE = CONFIG.files.users;

// Initialize files if they don't exist
async function initializeFiles() {
    try {
        await fs.access(ORDERS_FILE);
    } catch {
        await fs.writeFile(ORDERS_FILE, JSON.stringify([], null, 2));
    }
    
    try {
        await fs.access(ACTIVITY_FILE);
    } catch {
        await fs.writeFile(ACTIVITY_FILE, JSON.stringify([], null, 2));
    }
    
    try {
        await fs.access(USERS_FILE);
    } catch {
        // Create initial empty users file
        await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2));
        console.log('Created users.json - no users exist yet');
    }
}

// Activity logging helper
async function logActivity(type, orderId, details, userId = null) {
    try {
        const activityData = await fs.readFile(ACTIVITY_FILE, 'utf8');
        const activities = JSON.parse(activityData);
        
        activities.push({
            timestamp: new Date().toISOString(),
            type: type,
            orderId: orderId,
            userId: userId,
            details: details
        });
        
        await fs.writeFile(ACTIVITY_FILE, JSON.stringify(activities, null, 2));
        console.log(`Activity logged: ${type} for order ${orderId}${userId ? ` by user ${userId}` : ''}`);
    } catch (error) {
        console.error('Failed to log activity:', error);
    }
}

// Generate secure PIN
function generatePIN() {
    return crypto.randomInt(100000, 999999).toString();
}

// Generate secure user PIN for login
function generateUserPIN() {
    return crypto.randomInt(1000, 9999).toString();
}

// Auth middleware
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Load users and verify user still exists and is verified
        const usersData = await fs.readFile(USERS_FILE, 'utf8');
        const users = JSON.parse(usersData);
        const user = users.find(u => u.userId === decoded.userId);
        
        if (!user) {
            return res.status(403).json({ message: 'User not found' });
        }
        
        if (!user.verified) {
            return res.status(403).json({ message: 'Account not verified. Please contact an administrator.' });
        }
        
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Token verification failed:', error);
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
}

// ========== AUTH ENDPOINTS ==========

// Signup endpoint
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;
        
        // Validate inputs
        if (!email || !password || !fullName) {
            return res.status(400).json({ message: 'Email, password, and full name are required' });
        }
        
        // Validate email domain
        if (!email.toLowerCase().endsWith('@qgipr.com')) {
            return res.status(400).json({ message: 'Only @qgipr.com email addresses are allowed' });
        }
        
        // Password strength validation
        if (password.length < 8) {
            return res.status(400).json({ message: 'Password must be at least 8 characters long' });
        }
        
        // Load users
        const usersData = await fs.readFile(USERS_FILE, 'utf8');
        const users = JSON.parse(usersData);
        
        // Check if user already exists
        if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
            return res.status(409).json({ message: 'User with this email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generate user ID
        const userId = 'user_' + crypto.randomBytes(8).toString('hex');
        
        // Create new user (NOT verified by default)
        const newUser = {
            userId: userId,
            email: email.toLowerCase(),
            fullName: fullName,
            password: hashedPassword,
            verified: false, // MUST be manually set to true by admin
            pin: null, // PIN can be set later
            createdAt: new Date().toISOString(),
            lastLogin: null
        };
        
        users.push(newUser);
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        
        console.log(`New user registered: ${email} (userId: ${userId}) - AWAITING VERIFICATION`);
        
        res.json({
            success: true,
            message: 'Account created successfully. Please wait for administrator verification.',
            userId: userId,
            verified: false
        });
        
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Failed to create account' });
    }
});

// Login endpoint (email/password)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        
        // Load users
        const usersData = await fs.readFile(USERS_FILE, 'utf8');
        const users = JSON.parse(usersData);
        
        // Find user
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Check if verified
        if (!user.verified) {
            return res.status(403).json({ 
                message: 'Account not verified. Please contact an administrator.',
                verified: false
            });
        }
        
        // Update last login
        const userIndex = users.findIndex(u => u.userId === user.userId);
        users[userIndex].lastLogin = new Date().toISOString();
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        
        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.userId,
                email: user.email,
                fullName: user.fullName
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log(`User logged in: ${email}`);
        
        res.json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                userId: user.userId,
                email: user.email,
                fullName: user.fullName,
                hasPin: !!user.pin
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Login failed' });
    }
});

// PIN login endpoint
app.post('/api/auth/login-pin', async (req, res) => {
    try {
        const { email, pin } = req.body;
        
        if (!email || !pin) {
            return res.status(400).json({ message: 'Email and PIN are required' });
        }
        
        // Load users
        const usersData = await fs.readFile(USERS_FILE, 'utf8');
        const users = JSON.parse(usersData);
        
        // Find user
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Check if user has a PIN set
        if (!user.pin) {
            return res.status(400).json({ message: 'PIN not set for this account' });
        }
        
        // Verify PIN
        const validPin = await bcrypt.compare(pin, user.pin);
        
        if (!validPin) {
            return res.status(401).json({ message: 'Invalid PIN' });
        }
        
        // Check if verified
        if (!user.verified) {
            return res.status(403).json({ 
                message: 'Account not verified. Please contact an administrator.',
                verified: false
            });
        }
        
        // Update last login
        const userIndex = users.findIndex(u => u.userId === user.userId);
        users[userIndex].lastLogin = new Date().toISOString();
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        
        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.userId,
                email: user.email,
                fullName: user.fullName
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log(`User logged in via PIN: ${email}`);
        
        res.json({
            success: true,
            message: 'PIN login successful',
            token: token,
            user: {
                userId: user.userId,
                email: user.email,
                fullName: user.fullName,
                hasPin: true
            }
        });
        
    } catch (error) {
        console.error('PIN login error:', error);
        res.status(500).json({ message: 'PIN login failed' });
    }
});

// Set/Update PIN endpoint (requires authentication)
app.post('/api/auth/set-pin', authenticateToken, async (req, res) => {
    try {
        const { pin, currentPassword } = req.body;
        
        if (!pin || !currentPassword) {
            return res.status(400).json({ message: 'PIN and current password are required' });
        }
        
        // Validate PIN (must be 4 digits)
        if (!/^\d{4}$/.test(pin)) {
            return res.status(400).json({ message: 'PIN must be exactly 4 digits' });
        }
        
        // Load users
        const usersData = await fs.readFile(USERS_FILE, 'utf8');
        const users = JSON.parse(usersData);
        
        // Find user
        const userIndex = users.findIndex(u => u.userId === req.user.userId);
        const user = users[userIndex];
        
        // Verify current password
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid password' });
        }
        
        // Hash and set PIN
        const hashedPin = await bcrypt.hash(pin, 10);
        users[userIndex].pin = hashedPin;
        
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        
        console.log(`PIN set for user: ${user.email}`);
        
        res.json({
            success: true,
            message: 'PIN set successfully'
        });
        
    } catch (error) {
        console.error('Set PIN error:', error);
        res.status(500).json({ message: 'Failed to set PIN' });
    }
});

// Verify token endpoint (check if still valid)
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

// ========== ORIGINAL ENDPOINTS (UNCHANGED) ==========

// Save order endpoint (NO AUTH REQUIRED - kiosk needs to be public)
app.post('/api/orders', async (req, res) => {
    try {
        console.log('Received order:', req.body);
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        // Generate order ID if not present
        const orderId = req.body.orderId || 'QG' + crypto.randomBytes(5).toString('hex').toUpperCase();
        
        // Transform order to proper structure if it's in old format
        let order;
        if (req.body.dimensions && req.body.specifications) {
            // Already in new format
            order = {
                orderId: orderId,
                timestamp: req.body.timestamp || new Date().toISOString(),
                dimensions: req.body.dimensions,
                specifications: req.body.specifications,
                payment: req.body.payment || { method: req.body.paymentMethod || 'unknown' },
                status: req.body.status || 'pending',
                customerName: req.body.customerName || null,
                customerId: req.body.customerId || null,
                changePIN: null
            };
        } else {
            // Old flat format - transform it
            order = {
                orderId: orderId,
                timestamp: new Date().toISOString(),
                dimensions: {
                    width: req.body.width,
                    height: req.body.height
                },
                specifications: {
                    color: req.body.color,
                    thickness: req.body.thickness,
                    additions: req.body.additions || []
                },
                payment: {
                    method: req.body.payment || req.body.paymentMethod || 'unknown'
                },
                status: 'pending',
                customerName: req.body.customerName || null,
                customerId: req.body.customerId || null,
                changePIN: null
            };
        }
        
        orders.push(order);
        
        await fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Log activity
        await logActivity('order_created', order.orderId, {
            dimensions: order.dimensions,
            specifications: order.specifications
        });
        
        console.log(`Order ${order.orderId} saved successfully`);
        
        res.json({
            success: true,
            orderId: order.orderId,
            message: 'Order saved successfully'
        });
        
    } catch (error) {
        console.error('Error saving order:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save order'
        });
    }
});

// Get order by ID (NO AUTH - customer needs this)
app.get('/api/orders/:id', async (req, res) => {
    try {
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const order = orders.find(o => o.orderId === req.params.id);
        
        if (order) {
            res.json(order);
        } else {
            res.status(404).json({ message: 'Order not found' });
        }
        
    } catch (error) {
        console.error('Error fetching order:', error);
        res.status(500).json({ message: 'Failed to fetch order' });
    }
});

// Get all orders (REQUIRES AUTH - admin only)
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        res.json(orders);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders' });
    }
});

// Generate change PIN for an order (NO AUTH - customers need this)
app.post('/api/orders/:id/generate-pin', async (req, res) => {
    try {
        const orderId = req.params.id;
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const orderIndex = orders.findIndex(o => o.orderId === orderId);
        if (orderIndex === -1) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        // Generate new PIN
        const pin = generatePIN();
        orders[orderIndex].changePIN = pin;
        orders[orderIndex].pinGeneratedAt = new Date().toISOString();
        
        await fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Log activity (userId is null for customer-generated PINs)
        await logActivity('pin_generated', orderId, {
            generatedAt: orders[orderIndex].pinGeneratedAt
        }, null);
        
        console.log(`PIN generated for order ${orderId} (customer-initiated)`);
        
        res.json({
            success: true,
            orderId: orderId,
            pin: pin,
            message: 'Change PIN generated successfully'
        });
        
    } catch (error) {
        console.error('Error generating PIN:', error);
        res.status(500).json({ message: 'Failed to generate PIN' });
    }
});

// Verify PIN and allow order update (NO AUTH - customer needs this)
app.post('/api/orders/:id/verify-pin', async (req, res) => {
    try {
        const orderId = req.params.id;
        const { pin } = req.body;
        
        if (!pin) {
            return res.status(400).json({ message: 'PIN is required' });
        }
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const order = orders.find(o => o.orderId === orderId);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        if (order.changePIN !== pin) {
            // Log failed attempt
            await logActivity('pin_verification_failed', orderId, {
                attemptedPin: pin.substring(0, 2) + '****' // partial log for security
            });
            
            return res.status(401).json({ 
                success: false,
                message: 'Invalid PIN' 
            });
        }
        
        // Log successful verification
        await logActivity('pin_verified', orderId, {
            verifiedAt: new Date().toISOString()
        });
        
        res.json({
            success: true,
            message: 'PIN verified successfully',
            order: order
        });
        
    } catch (error) {
        console.error('Error verifying PIN:', error);
        res.status(500).json({ message: 'Failed to verify PIN' });
    }
});

// Update order status (REQUIRES AUTH)
app.patch('/api/orders/:id/status', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        const orderId = req.params.id;
        
        const validStatuses = ['pending', 'in-progress', 'ready', 'completed', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const orderIndex = orders.findIndex(o => o.orderId === orderId);
        if (orderIndex === -1) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        const oldStatus = orders[orderIndex].status;
        orders[orderIndex].status = status;
        orders[orderIndex].lastUpdated = new Date().toISOString();
        
        await fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Log activity
        await logActivity('status_updated', orderId, {
            oldStatus: oldStatus,
            newStatus: status
        }, req.user.userId);
        
        console.log(`Order ${orderId} status updated to ${status} by ${req.user.email}`);
        
        res.json({
            success: true,
            orderId: orderId,
            status: status,
            message: 'Order status updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).json({ message: 'Failed to update order status' });
    }
});

// Update order with PIN verification (NO AUTH - customer needs this)
app.put('/api/orders/:id', async (req, res) => {
    try {
        const orderId = req.params.id;
        const { pin, updatedOrder } = req.body;
        
        if (!pin) {
            return res.status(400).json({ message: 'PIN is required for order updates' });
        }
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const orderIndex = orders.findIndex(o => o.orderId === orderId);
        if (orderIndex === -1) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        // Verify PIN
        if (orders[orderIndex].changePIN !== pin) {
            await logActivity('order_update_failed', orderId, {
                reason: 'Invalid PIN'
            });
            
            return res.status(401).json({ 
                success: false,
                message: 'Invalid PIN' 
            });
        }
        
        // Store old order for logging
        const oldOrder = { ...orders[orderIndex] };
        
        // Update order
        updatedOrder.orderId = orderId;
        updatedOrder.lastUpdated = new Date().toISOString();
        updatedOrder.changePIN = orders[orderIndex].changePIN; // preserve PIN
        
        orders[orderIndex] = updatedOrder;
        
        await fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Log detailed changes
        await logActivity('order_updated', orderId, {
            changes: {
                dimensions: {
                    old: oldOrder.dimensions,
                    new: updatedOrder.dimensions
                },
                specifications: {
                    old: oldOrder.specifications,
                    new: updatedOrder.specifications
                },
                payment: {
                    old: oldOrder.payment,
                    new: updatedOrder.payment
                }
            }
        });
        
        console.log(`Order ${orderId} updated successfully`);
        
        res.json({
            success: true,
            order: updatedOrder,
            message: 'Order updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ message: 'Failed to update order' });
    }
});

// Update customer information (REQUIRES AUTH)
app.patch('/api/orders/:id/customer', authenticateToken, async (req, res) => {
    try {
        const orderId = req.params.id;
        const { customerName, customerId } = req.body;
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const orderIndex = orders.findIndex(o => o.orderId === orderId);
        if (orderIndex === -1) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        const oldCustomerName = orders[orderIndex].customerName;
        const oldCustomerId = orders[orderIndex].customerId;
        
        if (customerName !== undefined) {
            orders[orderIndex].customerName = customerName;
        }
        if (customerId !== undefined) {
            orders[orderIndex].customerId = customerId;
        }
        
        orders[orderIndex].lastUpdated = new Date().toISOString();
        
        await fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Log activity
        await logActivity('customer_info_updated', orderId, {
            old: {
                customerName: oldCustomerName,
                customerId: oldCustomerId
            },
            new: {
                customerName: orders[orderIndex].customerName,
                customerId: orders[orderIndex].customerId
            }
        }, req.user.userId);
        
        console.log(`Customer info updated for order ${orderId} by ${req.user.email}`);
        
        res.json({
            success: true,
            orderId: orderId,
            customerName: orders[orderIndex].customerName,
            customerId: orders[orderIndex].customerId,
            message: 'Customer information updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating customer info:', error);
        res.status(500).json({ message: 'Failed to update customer information' });
    }
});

// Delete order (REQUIRES AUTH)
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const orderId = req.params.id;
        
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const orderIndex = orders.findIndex(o => o.orderId === orderId);
        if (orderIndex === -1) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        const deletedOrder = orders[orderIndex];
        orders.splice(orderIndex, 1);
        
        await fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Log activity
        await logActivity('order_deleted', orderId, {
            deletedOrder: deletedOrder
        }, req.user.userId);
        
        console.log(`Order ${orderId} deleted by ${req.user.email}`);
        
        res.json({
            success: true,
            message: 'Order deleted successfully'
        });
        
    } catch (error) {
        console.error('Error deleting order:', error);
        res.status(500).json({ message: 'Failed to delete order' });
    }
});

// Get order statistics (REQUIRES AUTH)
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const ordersData = await fs.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(ordersData);
        
        const stats = orders.reduce((acc, order) => {
            acc.total++;
            acc.byStatus[order.status] = (acc.byStatus[order.status] || 0) + 1;
            
            const today = new Date().toDateString();
            const orderDate = new Date(order.timestamp).toDateString();
            if (orderDate === today) {
                acc.todayCount++;
            }
            
            return acc;
        }, {
            total: 0,
            todayCount: 0,
            byStatus: {}
        });
        
        res.json(stats);
        
    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({ message: 'Failed to get statistics' });
    }
});

// Get activity log (REQUIRES AUTH)
app.get('/api/activity', authenticateToken, async (req, res) => {
    try {
        const activityData = await fs.readFile(ACTIVITY_FILE, 'utf8');
        const activities = JSON.parse(activityData);
        res.json(activities);
    } catch (error) {
        console.error('Error fetching activity log:', error);
        res.status(500).json({ message: 'Failed to fetch activity log' });
    }
});

// Download activity log (REQUIRES AUTH)
app.get('/api/activity/download', authenticateToken, async (req, res) => {
    try {
        const activityData = await fs.readFile(ACTIVITY_FILE, 'utf8');
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=activity.json');
        res.send(activityData);
    } catch (error) {
        console.error('Error downloading activity log:', error);
        res.status(500).json({ message: 'Failed to download activity log' });
    }
});

// Start server
initializeFiles().then(() => {
    app.listen(PORT, () => {
        console.log(`\n========================================`);
        console.log(`\n${'='.repeat(60)}`);
        console.log(`QGI Glass Shop Server v0.6 (WITH AUTH)`);
        console.log(`${'='.repeat(60)}`);
        console.log(`\n📡 Server Info:`);
        console.log(`   Running on: http://localhost:${PORT}`);
        console.log(`   CORS Origin: ${CONFIG.cors.origin}`);
        console.log(`   JWT Secret: ${CONFIG.jwtSecret === process.env.JWT_SECRET ? 'From ENV ✓' : 'Default (CHANGE IN PROD)'}`);
        console.log(`\n📁 Data Files:`);
        console.log(`   Orders: ${ORDERS_FILE}`);
        console.log(`   Activity: ${ACTIVITY_FILE}`);
        console.log(`   Users: ${USERS_FILE}`);
        console.log(`\n🔐 Auth Features:`);
        console.log(`   - Email/Password login (@qgipr.com only)`);
        console.log(`   - 4-digit PIN login (optional)`);
        console.log(`   - Manual verification required for new accounts`);
        console.log(`   - JWT token authentication (24h expiry)`);
        console.log(`\n🔒 Protected Endpoints (require auth):`);
        console.log(`   - GET /api/orders (all orders)`);
        console.log(`   - DELETE /api/orders/:id`);
        console.log(`   - PATCH /api/orders/:id/status`);
        console.log(`   - PATCH /api/orders/:id/customer`);
        console.log(`   - POST /api/orders/:id/generate-pin`);
        console.log(`   - GET /api/stats`);
        console.log(`   - GET /api/activity`);
        console.log(`\n🌍 Public Endpoints (no auth):`);
        console.log(`   - POST /api/orders (create order)`);
        console.log(`   - GET /api/orders/:id (get single order)`);
        console.log(`   - PUT /api/orders/:id (update with PIN)`);
        console.log(`   - POST /api/orders/:id/verify-pin`);
	console.log(`   AUTIST PROGRAMMING REPRESENT`);
	console.log(`   VIBECODED AI PROGRAMMING REPRESENT`);
        console.log(`\n${'='.repeat(60)}\n`);
        console.log(`- POST /api/orders/:id/verify-pin`);
        console.log(`\nTo expose with ngrok, run:`);
        console.log(`ngrok http ${PORT}`);
        console.log(`========================================\n`);
    });
});