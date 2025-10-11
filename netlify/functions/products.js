const mongoose = require('mongoose');

const connectDB = async () => {
  if (mongoose.connections[0].readyState) return;
  await mongoose.connect(process.env.MONGODB_URI);
};

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, required: true },
  category: { type: String, required: true },
  stock: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': 'https://samriddhishop.netlify.app',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers };
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

  try {
    if (event.httpMethod === 'GET') {
      const products = await Product.find();
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(products)
      };
    }

    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  } catch (queryError) {
    console.error('Database query failed:', queryError);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch products' })
    };
  }
};