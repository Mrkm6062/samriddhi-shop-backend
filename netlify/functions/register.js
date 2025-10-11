const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

const connectDB = async () => {
  if (mongoose.connections[0].readyState) return;
  await mongoose.connect(process.env.MONGODB_URI);
};

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': 'https://samriddhishop.netlify.app',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    await connectDB();
  } catch (dbError) {
    console.error('Database connection failed:', dbError);
    return {
      statusCode: 503,
      headers,
      body: JSON.stringify({ error: 'Database unavailable' })
    };
  }

  let requestData;
  try {
    requestData = JSON.parse(event.body);
  } catch (parseError) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid JSON format' })
    };
  }

  const { name, email, password } = requestData;
  
  if (!name || !email || !password || password.length < 6) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid input data' })
    };
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    
    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({ message: 'User created successfully' })
    };
  } catch (userError) {
    console.error('User creation failed:', userError);
    if (userError.code === 11000) {
      return {
        statusCode: 409,
        headers,
        body: JSON.stringify({ error: 'Email already exists' })
      };
    }
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to create user' })
    };
  }
};