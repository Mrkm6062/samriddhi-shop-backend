import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { body, validationResult } from 'express-validator';
import dotenv from 'dotenv';
import crypto from 'crypto';
import Razorpay from 'razorpay';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://samriddhishop.netlify.app',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));

// Rate limiting (relaxed for better user experience)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // increased limit
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Relaxed rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, // increased from 5 to 50
  message: 'Too many authentication attempts, please try again later.'
});

app.use(express.json({ limit: '10mb' }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/samriddhishop', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  phone: { type: String, trim: true },
  wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  cart: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    quantity: { type: Number, default: 1 }
  }],
  addresses: [{
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String },
    zipCode: { type: String },
    country: { type: String, default: 'India' },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  originalPrice: { type: Number },
  discountPercentage: { type: Number, default: 0, min: 0, max: 100 },
  imageUrl: { type: String, required: true },
  images: [{ type: String }],
  category: { type: String, required: true },
  stock: { type: Number, default: 0, min: 0 },
  variants: [{
    size: String,
    color: String,
    stock: { type: Number, default: 0, min: 0 },
    sku: String
  }],
  highlights: [{ type: String }],
  specifications: [{
    key: { type: String, required: true },
    value: { type: String, required: true }
  }],
  warranty: { type: String },
  showHighlights: { type: Boolean, default: false },
  showSpecifications: { type: Boolean, default: false },
  showWarranty: { type: Boolean, default: false },
  enabled: { type: Boolean, default: true },
  ratings: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rating: { type: Number, min: 1, max: 5 },
    review: String,
    createdAt: { type: Date, default: Date.now }
  }],
  averageRating: { type: Number, default: 0 },
  totalRatings: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  orderNumber: { type: String, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String,
    price: Number,
    quantity: Number,
    selectedVariant: {
      size: String,
      color: String,
      stock: Number
    }
  }],
  total: { type: Number, required: true },
  status: { type: String, default: 'pending', enum: ['pending', 'processing', 'shipped', 'delivered'] },
  shippingAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  paymentMethod: { type: String, default: 'cod', enum: ['cod', 'razorpay'] },
  paymentStatus: { type: String, enum: ['pending', 'received'], default: 'pending' },
  courierDetails: {
    courierName: String,
    trackingNumber: String,
    estimatedDelivery: Date,
    shippedAt: Date
  },
  statusHistory: [{
    status: String,
    updatedAt: { type: Date, default: Date.now },
    updatedBy: String,
    notes: String
  }],
  paymentDetails: {
    razorpay_payment_id: String,
    razorpay_order_id: String,
    razorpay_signature: String,
  },
  couponCode: String,
  discount: { type: Number, default: 0 },
  shippingCost: { type: Number, default: 0 },
  tax: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

// Counter Schema for order numbers
const counterSchema = new mongoose.Schema({
  date: { type: String, required: true, unique: true },
  count: { type: Number, default: 0 }
});

const Counter = mongoose.model('Counter', counterSchema);

const Order = mongoose.model('Order', orderSchema);

// JWT Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key');
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// CSRF Protection
const csrfTokens = new Map();

const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const csrfProtection = (req, res, next) => {
  if (req.method === 'GET') return next();
  
  const token = req.headers['x-csrf-token'];
  const sessionId = req.headers['authorization'];
  
  if (!token || !csrfTokens.has(sessionId) || csrfTokens.get(sessionId) !== token) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  next();
};

// CSRF token endpoint (requires authentication)
app.get('/api/csrf-token', authenticateToken, (req, res) => {
  const token = generateCSRFToken();
  const sessionId = req.headers['authorization'];
  csrfTokens.set(sessionId, token);
  res.json({ csrfToken: token });
});

// Input validation middleware
const validateInput = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Admin middleware
const adminAuth = (req, res, next) => {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@samriddhishop.com';
  if (req.user.email !== adminEmail) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// API Routes

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ $or: [{ enabled: true }, { enabled: { $exists: false } }] }).sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate('ratings.userId', 'name');
    if (!product || (product.enabled === false)) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// User registration
app.post('/api/register', 
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('name').trim().isLength({ min: 1 })
  ],
  validateInput,
  async (req, res) => {
    try {
      const { name, email, password } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const user = new User({ name, email, password });
      await user.save();

      const token = jwt.sign(
        { userId: user._id }, 
        process.env.JWT_SECRET || 'fallback_secret_key',
        { expiresIn: '7d' }
      );

      res.status(201).json({
        message: 'User created successfully',
        token,
        user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
      });
    } catch (error) {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// User login
app.post('/api/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').exists()
  ],
  validateInput,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET || 'fallback_secret_key',
        { expiresIn: '7d' }
      );

      res.json({
        message: 'Login successful',
        token,
        user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
      });
    } catch (error) {
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// Add item to cart (for logged-in users)
app.post('/api/cart/add', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;
    
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // In a real app, you'd store cart in database
    // For simplicity, we're just validating the product exists
    res.json({ message: 'Item added to cart', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

// Get user orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .populate('items.productId');
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order for tracking
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('items.productId');
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Check if user owns the order
    if (order.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(order);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// Checkout
app.post('/api/checkout', 
  authenticateToken,
  [
    body('items').isArray({ min: 1 }),
    body('total').isNumeric({ min: 0 })
  ],
  validateInput,
  async (req, res) => {
    try {
      const { items, total } = req.body;

      // Validate all products exist and calculate total
      let calculatedTotal = 0;
      const orderItems = [];

      for (const item of items) {
        const product = await Product.findById(item._id);
        if (!product) {
          return res.status(404).json({ error: `Product ${item.name} not found` });
        }
        
        calculatedTotal += product.price * item.quantity;
        orderItems.push({
          productId: product._id,
          name: product.name,
          price: product.price,
          quantity: item.quantity,
          selectedVariant: item.selectedVariant
        });
      }

      // Verify total matches
      if (Math.abs(calculatedTotal - total) > 0.01) {
        return res.status(400).json({ error: 'Total amount mismatch' });
      }

      // Generate order number
      const now = new Date();
      const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`;
      
      const counter = await Counter.findOneAndUpdate(
        { date: dateStr },
        { $inc: { count: 1 } },
        { upsert: true, new: true }
      );
      
      const orderNumber = `${dateStr}${String(counter.count).padStart(4, '0')}`;

      const order = new Order({
        orderNumber,
        userId: req.user._id,
        items: orderItems,
        total: calculatedTotal,
        status: 'pending',
        shippingAddress: req.body.shippingAddress,
        paymentMethod: req.body.paymentMethod || 'cod',
        paymentStatus: req.body.paymentMethod !== 'cod' ? 'received' : 'pending',
        couponCode: req.body.couponCode,
        discount: req.body.discount || 0,
        shippingCost: req.body.shippingCost || 0,
        tax: req.body.tax || 0,
        paymentDetails: {
          razorpay_payment_id: req.body.razorpay_payment_id,
          razorpay_order_id: req.body.razorpay_order_id,
          razorpay_signature: req.body.razorpay_signature,
        }
      });

      await order.save();
      
      // Update coupon usage if coupon was used
      if (req.body.couponCode && req.body.couponId) {
        await Coupon.findByIdAndUpdate(req.body.couponId, {
          $inc: { usageCount: 1 },
          $push: {
            usedBy: {
              userId: req.user._id,
              orderId: order._id,
              usedAt: new Date()
            }
          }
        });
      }

      res.json({ 
        message: 'Order placed successfully', 
        orderId: order._id,
        total: calculatedTotal
      });
    } catch (error) {
      res.status(500).json({ error: 'Checkout failed' });
    }
  }
);

// Create Razorpay Order
app.post('/api/payment/create-order', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    const options = {
      amount: Math.round(amount * 100), // amount in the smallest currency unit
      currency: "INR",
      receipt: `receipt_order_${crypto.randomBytes(4).toString('hex')}`
    };

    const order = await razorpay.orders.create(options);

    if (!order) {
      return res.status(500).send("Error creating Razorpay order");
    }

    res.json({
      orderId: order.id,
      amount: order.amount,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    res.status(500).send("Error creating Razorpay order");
  }
});

// Verify Razorpay Payment
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');

    if (expectedSignature === razorpay_signature) {
      res.json({ success: true, message: "Payment verified successfully" });
    } else {
      res.status(400).json({ success: false, message: "Payment verification failed" });
    }
  } catch (error) {
    res.status(500).json({ error: 'Payment verification failed' });
  }
});

app.post('/api/create-admin', async (req, res) => {
  // This endpoint is intentionally left less secure for initial setup.
  // In a real production environment, this should be removed or heavily secured.
  // ... (implementation from server11.js can be copied here if needed)
}
);

// Update order status (for admin/testing)
app.patch('/api/orders/:id/status', 
  authenticateToken,
  [
    body('status').isIn(['pending', 'processing', 'shipped', 'delivered'])
  ],
  validateInput,
  async (req, res) => {
    try {
      const { status, courierName, trackingNumber, estimatedDelivery, notes } = req.body;
      const order = await Order.findById(req.params.id);
      
      if (!order) {
        return res.status(404).json({ error: 'Order not found' });
      }

      // Allow admin or order owner to update status
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@samriddhishop.com';
      if (req.user.email !== adminEmail && order.userId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // Add to status history
      order.statusHistory.push({
        status: order.status,
        updatedAt: new Date(),
        updatedBy: req.user.email,
        notes: notes || `Status changed to ${status}`
      });

      order.status = status;

      // If a COD order is marked as delivered, automatically mark payment as received
      if (status === 'delivered' && order.paymentMethod === 'cod') {
        order.paymentStatus = 'received';
      }

      // If status is shipped, update courier details and reduce stock
      if (status === 'shipped' && (courierName || trackingNumber)) {
        order.courierDetails = {
          courierName: courierName || order.courierDetails?.courierName,
          trackingNumber: trackingNumber || order.courierDetails?.trackingNumber,
          estimatedDelivery: estimatedDelivery ? new Date(estimatedDelivery) : order.courierDetails?.estimatedDelivery,
          shippedAt: new Date()
        };
        
        // Reduce stock when shipped
        for (const item of order.items) {
          if (item.selectedVariant) {
            // Reduce variant stock
            await Product.findOneAndUpdate(
              { 
                _id: item.productId,
                'variants.size': item.selectedVariant.size,
                'variants.color': item.selectedVariant.color
              },
              { $inc: { 'variants.$.stock': -item.quantity } }
            );
          } else {
            // Reduce main product stock
            await Product.findByIdAndUpdate(item.productId, {
              $inc: { stock: -item.quantity }
            });
          }
        }
      }

      await order.save();

      res.json({ message: 'Order status updated', order });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update order status' });
    }
  }
);

// Get orders by date range for admin
app.get('/api/admin/orders/date-range', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;
    
    let query = {};
    
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate + 'T23:59:59.999Z')
      };
    }
    
    if (status && status !== 'all') {
      query.status = status;
    }
    
    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .populate('userId', 'name email phone');
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get order analytics for admin
app.get('/api/admin/analytics', authenticateToken, adminAuth, async (req, res) => {
  try {
    const today = new Date();
    const startOfDay = new Date(today.setHours(0, 0, 0, 0));
    const startOfWeek = new Date(today.setDate(today.getDate() - 7));
    const startOfMonth = new Date(today.setMonth(today.getMonth() - 1));
    
    const [todayOrders, weekOrders, monthOrders, totalOrders, statusCounts] = await Promise.all([
      Order.countDocuments({ createdAt: { $gte: startOfDay } }),
      Order.countDocuments({ createdAt: { $gte: startOfWeek } }),
      Order.countDocuments({ createdAt: { $gte: startOfMonth } }),
      Order.countDocuments(),
      Order.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ])
    ]);
    
    const revenue = await Order.aggregate([
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    
    res.json({
      todayOrders,
      weekOrders,
      monthOrders,
      totalOrders,
      statusCounts,
      totalRevenue: revenue[0]?.total || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
app.put('/api/profile',
  authenticateToken,
  csrfProtection,
  [
    body('name').trim().isLength({ min: 1 }),
    body('email').isEmail().normalizeEmail(),
    body('phone').optional().trim()
  ],
  validateInput,
  async (req, res) => {
    try {
      const { name, email, phone } = req.body;
      
      const existingUser = await User.findOne({ email, _id: { $ne: req.user._id } });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already in use' });
      }

      const user = await User.findByIdAndUpdate(
        req.user._id,
        { name, email, phone },
        { new: true }
      ).select('-password');

      res.json({ 
        message: 'Profile updated successfully',
        user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
);

// Change password
app.put('/api/change-password',
  authenticateToken,
  csrfProtection,
  [
    body('currentPassword').exists(),
    body('newPassword').isLength({ min: 6 })
  ],
  validateInput,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      
      const user = await User.findById(req.user._id);
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 12);
      await User.findByIdAndUpdate(req.user._id, { password: hashedPassword });

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to change password' });
    }
  }
);

// Add address
app.post('/api/addresses',
  authenticateToken,
  csrfProtection,
  [
    body('street').trim().isLength({ min: 1 }),
    body('city').trim().isLength({ min: 1 })
  ],
  validateInput,
  async (req, res) => {
    try {
      const { street, city, state, zipCode, country } = req.body;
      
      const user = await User.findById(req.user._id);
      user.addresses.push({ street, city, state, zipCode, country: country || 'India' });
      await user.save();

      res.json({ message: 'Address added successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to add address' });
    }
  }
);

// Delete address
app.delete('/api/addresses/:id', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.addresses = user.addresses.filter(addr => addr._id.toString() !== req.params.id);
    await user.save();

    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Coupon Schema
const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true },
  discount: { type: Number, required: true },
  type: { type: String, enum: ['percentage', 'fixed'], default: 'percentage' },
  minAmount: { type: Number, default: 0 },
  maxDiscount: { type: Number },
  expiryDate: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  oneTimeUse: { type: Boolean, default: false },
  usageCount: { type: Number, default: 0 },
  usedBy: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    usedAt: { type: Date, default: Date.now },
    orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Coupon = mongoose.model('Coupon', couponSchema);

// Settings Schema
const settingsSchema = new mongoose.Schema({
  shippingCost: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// Banner Schema
const bannerSchema = new mongoose.Schema({
  title: { type: String, default: 'Welcome to SamriddhiShop' },
  subtitle: { type: String, default: 'Discover amazing products at great prices' },
  buttonText: { type: String, default: 'Shop Now' },
  backgroundImage: { type: String, default: '' },
  isActive: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});

const Banner = mongoose.model('Banner', bannerSchema);

// Contact Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, lowercase: true },
  subject: { type: String, required: true, trim: true },
  message: { type: String, required: true, trim: true },
  status: { type: String, enum: ['new', 'read', 'replied'], default: 'new' },
  createdAt: { type: Date, default: Date.now }
});

const Contact = mongoose.model('Contact', contactSchema);

// Admin - Get all products
app.get('/api/admin/products', authenticateToken, adminAuth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Admin - Add product
app.post('/api/admin/products', authenticateToken, adminAuth, csrfProtection, async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.json({ message: 'Product added successfully', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// Admin - Update product
app.put('/api/admin/products/:id', authenticateToken, adminAuth, csrfProtection, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ message: 'Product updated successfully', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Admin - Toggle product status
app.patch('/api/admin/products/:id/toggle', authenticateToken, adminAuth, csrfProtection, async (req, res) => {
  try {
    const { enabled } = req.body;
    const product = await Product.findByIdAndUpdate(req.params.id, { enabled }, { new: true });
    res.json({ message: 'Product status updated', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update product status' });
  }
});

// Admin - Get all orders
app.get('/api/admin/orders', authenticateToken, adminAuth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).populate('userId', 'name email phone');
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Admin - Get all coupons
app.get('/api/admin/coupons', authenticateToken, adminAuth, async (req, res) => {
  try {
    const coupons = await Coupon.find().sort({ createdAt: -1 });
    res.json(coupons);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Admin - Get all users
app.get('/api/admin/users', authenticateToken, adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    
    // Get order stats for all users in single aggregation
    const userStats = await Order.aggregate([
      { $match: { status: 'delivered' } },
      { $group: {
        _id: '$userId',
        orderCount: { $sum: 1 },
        totalAmount: { $sum: '$total' }
      }}
    ]);
    
    const statsMap = new Map(userStats.map(stat => [stat._id.toString(), stat]));
    
    const usersWithStats = users.map(user => {
      const stats = statsMap.get(user._id.toString()) || { orderCount: 0, totalAmount: 0 };
      return {
        ...user.toObject(),
        orderCount: stats.orderCount,
        totalAmount: stats.totalAmount
      };
    });
    
    res.json(usersWithStats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin - Create coupon
app.post('/api/admin/coupons', authenticateToken, adminAuth, async (req, res) => {
  try {
    const allowedFields = ['code', 'discount', 'type', 'minAmount', 'maxDiscount', 'expiryDate', 'oneTimeUse'];
    const couponData = {};
    
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        couponData[field] = req.body[field];
      }
    });
    
    const coupon = new Coupon(couponData);
    await coupon.save();
    res.json({ message: 'Coupon created successfully', coupon });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create coupon' });
  }
});

// Admin - Toggle coupon status
app.patch('/api/admin/coupons/:id/toggle', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { isActive } = req.body;
    const coupon = await Coupon.findByIdAndUpdate(req.params.id, { isActive }, { new: true });
    res.json({ message: 'Coupon status updated', coupon });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update coupon status' });
  }
});

// Admin - Get coupon usage report
app.get('/api/admin/coupons/report', authenticateToken, adminAuth, async (req, res) => {
  try {
    const coupons = await Coupon.find()
      .populate('usedBy.userId', 'name email')
      .populate('usedBy.orderId', 'orderNumber total')
      .sort({ createdAt: -1 });
    res.json(coupons);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch coupon report' });
  }
});

// Apply coupon
app.post('/api/apply-coupon', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const { code, total } = req.body;
    const coupon = await Coupon.findOne({ 
      code: code.toUpperCase(), 
      isActive: true, 
      expiryDate: { $gt: new Date() } 
    });
    
    if (!coupon) {
      return res.status(400).json({ error: 'Invalid or expired coupon' });
    }
    
    if (total < coupon.minAmount) {
      return res.status(400).json({ error: `Minimum order amount is ₹${coupon.minAmount}` });
    }
    
    // Check if user already used this coupon (for one-time use coupons)
    if (coupon.oneTimeUse && coupon.usedBy.some(usage => usage.userId.toString() === req.user._id.toString())) {
      return res.status(400).json({ error: 'Coupon already used by you' });
    }
    
    let discount = 0;
    if (coupon.type === 'percentage') {
      discount = Math.round((total * coupon.discount) / 100);
      if (coupon.maxDiscount && discount > coupon.maxDiscount) {
        discount = coupon.maxDiscount;
      }
    } else {
      discount = coupon.discount;
    }
    
    res.json({ discount, message: 'Coupon applied successfully', couponId: coupon._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to apply coupon' });
  }
});

// Get shipping cost
app.get('/api/shipping-cost', async (req, res) => {
  try {
    const settings = await Settings.findOne();
    res.json({ cost: settings?.shippingCost || 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch shipping cost' });
  }
});

// Add product rating
app.post('/api/products/:id/rating', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const { rating, review } = req.body;
    const productId = req.params.id;
    
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // Check if user already rated this product
    const existingRating = product.ratings.find(r => r.userId.toString() === req.user._id.toString());
    
    if (existingRating) {
      // Update existing rating
      existingRating.rating = rating;
      existingRating.review = review;
    } else {
      // Add new rating
      product.ratings.push({
        userId: req.user._id,
        rating,
        review
      });
    }
    
    // Calculate average rating
    const totalRatings = product.ratings.length;
    const avgRating = product.ratings.reduce((sum, r) => sum + r.rating, 0) / totalRatings;
    
    product.averageRating = Math.round(avgRating * 10) / 10;
    product.totalRatings = totalRatings;
    
    await product.save();
    
    res.json({ message: 'Rating added successfully', averageRating: product.averageRating });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add rating' });
  }
});

// Admin - Update shipping cost
app.put('/api/admin/shipping', authenticateToken, adminAuth, csrfProtection, async (req, res) => {
  try {
    const { cost } = req.body;
    await Settings.findOneAndUpdate({}, { shippingCost: cost }, { upsert: true });
    res.json({ message: 'Shipping cost updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update shipping cost' });
  }
});

// Get banner settings
app.get('/api/banner', async (req, res) => {
  try {
    const banner = await Banner.findOne({ isActive: true }) || new Banner();
    res.json(banner);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch banner' });
  }
});

// Admin - Update banner
app.put('/api/admin/banner', authenticateToken, adminAuth, csrfProtection, async (req, res) => {
  try {
    const banner = await Banner.findOneAndUpdate(
      { isActive: true },
      { ...req.body, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    res.json({ message: 'Banner updated successfully', banner });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update banner' });
  }
});

// Get user's wishlist
app.get('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('wishlist');
    res.json({ 
      wishlist: user.wishlist || [],
      products: user.wishlist || []
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get wishlist' });
  }
});

// Get user's cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('cart.productId');
    const cartItems = user.cart.map(item => ({
      ...item.productId.toObject(),
      quantity: item.quantity
    }));
    res.json({ cart: cartItems });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get cart' });
  }
});

// Update user's cart
app.post('/api/cart', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const { cart } = req.body;
    const user = await User.findById(req.user._id);
    user.cart = cart.map(item => ({
      productId: item._id,
      quantity: item.quantity
    }));
    await user.save();
    res.json({ message: 'Cart updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

// Add to wishlist
app.post('/api/wishlist/:id', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const productId = req.params.id;
    const user = await User.findById(req.user._id);
    
    if (user.wishlist.includes(productId)) {
      return res.status(400).json({ error: 'Product already in wishlist' });
    }
    
    user.wishlist.push(productId);
    await user.save();
    
    res.json({ message: 'Product added to wishlist' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add to wishlist' });
  }
});

// Remove from wishlist
app.delete('/api/wishlist/:id', authenticateToken, csrfProtection, async (req, res) => {
  try {
    const productId = req.params.id;
    const user = await User.findById(req.user._id);
    
    user.wishlist = user.wishlist.filter(id => id.toString() !== productId);
    await user.save();
    
    res.json({ message: 'Product removed from wishlist' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove from wishlist' });
  }
});

// Contact form submission
app.post('/api/contact',
  [
    body('name').trim().isLength({ min: 1 }),
    body('email').isEmail().normalizeEmail(),
    body('subject').trim().isLength({ min: 1 }),
    body('message').trim().isLength({ min: 10 })
  ],
  validateInput,
  async (req, res) => {
    try {
      const { name, email, subject, message } = req.body;
      
      const contact = new Contact({
        name,
        email,
        subject,
        message
      });
      
      await contact.save();
      
      res.json({ message: 'Message sent successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to send message' });
    }
  }
);

// Admin - Get all contact messages
app.get('/api/admin/contacts', authenticateToken, adminAuth, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch contact messages' });
  }
});

// Admin - Update contact message status
app.patch('/api/admin/contacts/:id/status', authenticateToken, adminAuth, csrfProtection, async (req, res) => {
  try {
    const { status } = req.body;
    await Contact.findByIdAndUpdate(req.params.id, { status });
    res.json({ message: 'Status updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Create admin account (bypasses rate limiting)
app.post('/api/create-admin', csrfProtection, async (req, res) => {
  try {
    const adminEmail = 'admin@samriddhishop.com';
    const { password } = req.body;
    
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const existingUser = await User.findOne({ email: adminEmail });
    if (existingUser) {
      return res.status(400).json({ error: 'Admin account already exists' });
    }
    
    const adminUser = new User({
      name: 'Admin',
      email: adminEmail,
      password: password
    });
    
    await adminUser.save();
    
    const token = jwt.sign(
      { userId: adminUser._id },
      process.env.JWT_SECRET || 'fallback_secret_key',
      { expiresIn: '7d' }
    );
    
    res.json({
      message: 'Admin account created successfully',
      token,
      user: { id: adminUser._id, name: adminUser.name, email: adminUser.email }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create admin account' });
  }
});

// Seed sample products (for development)
app.post('/api/seed', async (req, res) => {
  try {
    await Product.deleteMany({});
    
    const sampleProducts = [
      {
        name: 'Wireless Headphones',
        description: 'High-quality wireless headphones with noise cancellation',
        price: 2999,
        imageUrl: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500',
        category: 'Electronics'
      },
      {
        name: 'Smart Watch',
        description: 'Feature-rich smartwatch with health monitoring',
        price: 5999,
        imageUrl: 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=500',
        category: 'Electronics'
      },
      {
        name: 'Coffee Maker',
        description: 'Automatic coffee maker with programmable settings',
        price: 2399,
        imageUrl: 'https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=500',
        category: 'Appliances'
      },
      {
        name: 'Running Shoes',
        description: 'Comfortable running shoes for all terrains',
        price: 3899,
        imageUrl: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=500',
        category: 'Sports'
      },
      {
        name: 'Laptop Backpack',
        description: 'Durable laptop backpack with multiple compartments',
        price: 1499,
        imageUrl: 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=500',
        category: 'Accessories'
      },
      {
        name: 'Bluetooth Speaker',
        description: 'Portable Bluetooth speaker with excellent sound quality',
        price: 1799,
        imageUrl: 'https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?w=500',
        category: 'Electronics'
      }
    ];

    await Product.insertMany(sampleProducts);
    
    // Create admin user if doesn't exist
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@samriddhishop.com';
    const adminPassword = process.env.ADMIN_PASSWORD;
    
    if (!adminPassword) {
      return res.status(400).json({ error: 'ADMIN_PASSWORD environment variable is required' });
    }
    
    const adminExists = await User.findOne({ email: adminEmail });
    if (!adminExists) {
      const adminUser = new User({
        name: 'Admin',
        email: adminEmail,
        password: adminPassword
      });
      await adminUser.save();
    }
    
    res.json({ 
      message: 'Sample products and admin user created successfully'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to seed products' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
