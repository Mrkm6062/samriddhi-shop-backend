const express = require('express');
const serverless = require('serverless-http');

// Lazy load modules
let mongoose, cors, helmet, rateLimit, expressValidator, bcrypt, jwt;

const loadModules = async () => {
  if (!mongoose) {
    mongoose = require('mongoose');
    cors = require('cors');
    helmet = require('helmet');
    rateLimit = require('express-rate-limit');
    expressValidator = require('express-validator');
    bcrypt = require('bcrypt');
    jwt = require('jsonwebtoken');
  }
};

const app = express();

// Initialize middleware after loading modules
const initializeMiddleware = async () => {
  await loadModules();
  
  app.use(helmet());
  app.use(cors({
    origin: ['https://samriddhishop.netlify.app', 'http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));
  app.use(express.json());
  
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
  });
  app.use(limiter);
};

// MongoDB connection
const connectDB = async () => {
  if (mongoose.connections[0].readyState) return;
  await mongoose.connect(process.env.MONGODB_URI);
};

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, required: true },
  category: { type: String, required: true },
  stock: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Contact = mongoose.model('Contact', contactSchema);

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/products', async (req, res) => {
  await initializeMiddleware();
  await connectDB();
  const products = await Product.find();
  res.json(products);
});

app.post('/register', async (req, res) => {
  await initializeMiddleware();
  
  const { body, validationResult } = expressValidator;
  const validators = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('name').trim().isLength({ min: 1 })
  ];
  
  await Promise.all(validators.map(v => v.run(req)));
  await connectDB();
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 12);
  
  try {
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/login', async (req, res) => {
  await initializeMiddleware();
  await connectDB();
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
  res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
});

app.post('/contact', async (req, res) => {
  await initializeMiddleware();
  await connectDB();
  const contact = new Contact(req.body);
  await contact.save();
  res.status(201).json({ message: 'Message sent successfully' });
});

app.get('/contacts', authenticateToken, async (req, res) => {
  await initializeMiddleware();
  await connectDB();
  const contacts = await Contact.find().sort({ createdAt: -1 });
  res.json(contacts);
});

app.post('/seed', async (req, res) => {
  await initializeMiddleware();
  await connectDB();
  const sampleProducts = [
    {
      name: "Premium Wireless Headphones",
      description: "High-quality wireless headphones with noise cancellation",
      price: 2999,
      imageUrl: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500",
      category: "Electronics"
    }
  ];
  
  await Product.insertMany(sampleProducts);
  res.json({ message: 'Sample data seeded successfully' });
});

module.exports.handler = serverless(app);