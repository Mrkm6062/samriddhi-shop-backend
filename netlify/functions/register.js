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
    
    const { name, email, password } = JSON.parse(event.body);
    
    if (!name || !email || !password || password.length < 6) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid input data' })
      };
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    
    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({ message: 'User created successfully' })
    };
  } catch (error) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Email already exists' })
    };
  }
};